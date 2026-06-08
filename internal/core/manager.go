package core

import (
	"context"
	"errors"
	"os"
	"sort"
	"sync"
	"time"
)

type Manager struct {
	store   *Store
	mu      sync.RWMutex
	runners map[string]*Runner
	status  map[string]RuntimeStatus
}

func NewManager(store *Store) *Manager {
	return &Manager{
		store:   store,
		runners: map[string]*Runner{},
		status:  map[string]RuntimeStatus{},
	}
}

func (m *Manager) StartEnabled() {
	for _, cfg := range m.store.ListInstances() {
		if cfg.Enabled {
			_ = m.Start(cfg.ID)
		}
	}
}

func (m *Manager) List() []InstanceSnapshot {
	items := m.store.ListInstances()
	out := make([]InstanceSnapshot, 0, len(items))

	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, cfg := range items {
		out = append(out, InstanceSnapshot{
			Config:  cfg,
			Runtime: m.statusForLocked(cfg.ID),
		})
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].Config.Name < out[j].Config.Name
	})
	return out
}

func (m *Manager) Snapshot(id string) (InstanceSnapshot, bool) {
	cfg, ok := m.store.GetInstance(id)
	if !ok {
		return InstanceSnapshot{}, false
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	return InstanceSnapshot{Config: cfg, Runtime: m.statusForLocked(id)}, true
}

func (m *Manager) Start(id string) error {
	cfg, ok := m.store.GetInstance(id)
	if !ok {
		return os.ErrNotExist
	}

	m.mu.Lock()
	if _, exists := m.runners[id]; exists {
		m.mu.Unlock()
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	runner := NewRunner(cfg, m.report)
	seed := m.statusForLocked(id)
	if seed.PublicAddress == "" {
		if persisted, ok := m.store.RuntimeStatus(id); ok {
			seed = persisted
		}
	}
	runner.seedRuntime(seed)
	m.runners[id] = runner
	m.setStatusLocked(id, StateStarting, "", nil)
	m.mu.Unlock()

	go func() {
		runner.Run(ctx)
		cancel()

		m.mu.Lock()
		if m.runners[id] == runner {
			delete(m.runners, id)
			current := m.statusForLocked(id)
			if current.State != StateError {
				m.setStatusLocked(id, StateStopped, "", nil)
			}
		}
		m.mu.Unlock()
	}()

	return nil
}

func (m *Manager) Stop(id string) error {
	m.mu.Lock()
	runner, ok := m.runners[id]
	if !ok {
		current := m.statusForLocked(id)
		message := "instance stopped"
		if current.State == StateStopped {
			message = ""
		}
		m.setStatusLocked(id, StateStopped, message, nil)
		m.mu.Unlock()
		return nil
	}
	m.setStatusLocked(id, StateStopping, "stopping instance", nil)
	m.mu.Unlock()

	runner.Stop()
	select {
	case <-runner.Done():
	case <-time.After(5 * time.Second):
		return errors.New("实例停止超时，请稍后再试")
	}
	return nil
}

func (m *Manager) StopAll() {
	m.mu.RLock()
	runners := make([]*Runner, 0, len(m.runners))
	for _, runner := range m.runners {
		runners = append(runners, runner)
	}
	m.mu.RUnlock()

	for _, runner := range runners {
		runner.Stop()
	}
}

func (m *Manager) ApplyConfig(cfg InstanceConfig) {
	if cfg.Enabled {
		_ = m.Start(cfg.ID)
	}
}

func (m *Manager) ReplaceConfig(oldCfg, cfg InstanceConfig, wasRunning bool) error {
	mappingChanged := publicMappingConfigChanged(oldCfg, cfg)
	if !cfg.Enabled {
		if wasRunning {
			err := m.Stop(cfg.ID)
			if mappingChanged {
				m.clearRuntime(cfg.ID)
			}
			return err
		}
		return nil
	}

	if !wasRunning {
		if mappingChanged {
			m.clearRuntime(cfg.ID)
		}
		return m.Start(cfg.ID)
	}

	m.mu.Lock()
	runner, ok := m.runners[cfg.ID]
	if !ok {
		m.mu.Unlock()
		if mappingChanged {
			m.clearRuntime(cfg.ID)
		}
		return m.Start(cfg.ID)
	}
	m.setStatusLocked(cfg.ID, StateStopping, "restarting instance", nil)
	m.mu.Unlock()

	runner.Stop()
	select {
	case <-runner.Done():
	case <-time.After(30 * time.Second):
		return errors.New("旧实例停止超时，请稍后再试")
	}
	m.mu.Lock()
	if m.runners[cfg.ID] == runner {
		delete(m.runners, cfg.ID)
	}
	m.mu.Unlock()
	if mappingChanged {
		m.clearRuntime(cfg.ID)
	}
	return m.Start(cfg.ID)
}

func publicMappingConfigChanged(oldCfg, newCfg InstanceConfig) bool {
	if oldCfg.ID == "" {
		return true
	}
	return oldCfg.Protocol != newCfg.Protocol ||
		oldCfg.BindAddress != newCfg.BindAddress ||
		oldCfg.BindPort != newCfg.BindPort ||
		oldCfg.Interface != newCfg.Interface ||
		oldCfg.FWMark != newCfg.FWMark
}

func (m *Manager) clearRuntime(id string) {
	m.mu.Lock()
	st := m.statusForLocked(id)
	st.PublicAddress = ""
	st.PublicPort = 0
	st.PublicStableSince = time.Time{}
	st.PublicUpdatedAt = time.Time{}
	st.PrivateAddress = ""
	st.PrivatePort = 0
	st.Protocol = ""
	st.PortCheck = PortCheck{}
	m.status[id] = st
	m.mu.Unlock()
	_ = m.store.ClearRuntimeStatus(id)
}

func (m *Manager) IsRunning(id string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	_, ok := m.runners[id]
	return ok
}

func (m *Manager) report(id string, update RuntimeStatus) {
	m.mu.Lock()
	defer m.mu.Unlock()

	current := m.statusForLocked(id)
	if update.State != "" {
		current.State = update.State
		if update.State != StateError && update.LastError == "" {
			current.LastError = ""
		}
	}
	if update.StartedAt != nil {
		current.StartedAt = update.StartedAt
	}
	if !update.LastChange.IsZero() {
		current.LastChange = update.LastChange
	}
	if update.PublicAddress != "" {
		current.PublicAddress = update.PublicAddress
	}
	if update.PublicPort != 0 {
		current.PublicPort = update.PublicPort
	}
	if !update.PublicStableSince.IsZero() {
		current.PublicStableSince = update.PublicStableSince
	}
	if !update.PublicUpdatedAt.IsZero() {
		current.PublicUpdatedAt = update.PublicUpdatedAt
	}
	if update.PrivateAddress != "" {
		current.PrivateAddress = update.PrivateAddress
	}
	if update.PrivatePort != 0 {
		current.PrivatePort = update.PrivatePort
	}
	if update.Protocol != "" {
		current.Protocol = update.Protocol
	}
	if update.LastError != "" {
		current.LastError = update.LastError
	}
	if update.KeepAlive.State != "" {
		next := update.KeepAlive
		if next.State == KeepAliveConnected &&
			current.KeepAlive.State == KeepAliveConnected &&
			next.Protocol == current.KeepAlive.Protocol &&
			next.Address == current.KeepAlive.Address &&
			next.Port == current.KeepAlive.Port &&
			!current.KeepAlive.ConnectedAt.IsZero() {
			next.ConnectedAt = current.KeepAlive.ConnectedAt
		}
		current.KeepAlive = next
	}
	if update.PortCheck.State != "" {
		current.PortCheck = update.PortCheck
	}
	if len(update.Logs) > 0 {
		current.Logs = append(current.Logs, update.Logs...)
		if len(current.Logs) > 100 {
			current.Logs = current.Logs[len(current.Logs)-100:]
		}
	}
	if current.LastChange.IsZero() {
		current.LastChange = time.Now()
	}
	m.status[id] = current
	if update.PublicAddress != "" || update.PublicPort != 0 || !update.PublicUpdatedAt.IsZero() {
		_ = m.store.SaveRuntimeStatus(id, current)
	}
}

func (m *Manager) statusForLocked(id string) RuntimeStatus {
	if st, ok := m.status[id]; ok {
		if st.Logs == nil {
			st.Logs = []LogEntry{}
		}
		return st
	}
	return RuntimeStatus{
		State:      StateStopped,
		LastChange: time.Now(),
		Logs:       []LogEntry{},
	}
}

func (m *Manager) setStatusLocked(id, state, message string, err error) {
	st := m.statusForLocked(id)
	st.State = state
	st.LastChange = time.Now()
	if err != nil {
		st.LastError = err.Error()
		st.Logs = append(st.Logs, LogEntry{At: time.Now(), Level: "error", Message: err.Error()})
	} else if message != "" {
		st.LastError = ""
		st.Logs = append(st.Logs, LogEntry{At: time.Now(), Level: "info", Message: message})
	}
	if len(st.Logs) > 100 {
		st.Logs = st.Logs[len(st.Logs)-100:]
	}
	m.status[id] = st
}

var (
	errStopped       = errors.New("instance stopped")
	errSessionClosed = errors.New("session closed")
)
