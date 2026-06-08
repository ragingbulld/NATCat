package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Store struct {
	path string
	mu   sync.RWMutex
	db   Database
}

func OpenStore(path, setupUser, setupPassword string) (*Store, string, error) {
	store := &Store{path: path}
	raw, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(raw, &store.db); err != nil {
			return nil, "", err
		}
		store.normalizeLocked()
		return store, "", nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, "", err
	}

	generated := ""
	if setupPassword == "" {
		setupPassword, err = randomSecret(18)
		if err != nil {
			return nil, "", err
		}
		generated = setupPassword
	}

	admin, err := NewAdminCredential(setupUser, setupPassword)
	if err != nil {
		return nil, "", err
	}
	admin.LastPassword = time.Now()

	store.db = Database{
		Version: 1,
		Admin:   admin,
		Options: SystemOptions{
			SessionHours: 12,
			STUNServers:  defaultSTUNServers(),
			HTTPServers:  defaultHTTPServers(),
			QUICServers:  defaultQUICServers(),
		},
		Items: []InstanceConfig{},
	}
	if err := store.saveLocked(); err != nil {
		return nil, "", err
	}
	return store, generated, nil
}

func (s *Store) Admin() AdminCredential {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshAdminFromDiskLocked()
	return s.db.Admin
}

func ChangeAdminPassword(path, username, password string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("data file does not exist: %s", path)
		}
		return err
	}

	var db Database
	if err := json.Unmarshal(raw, &db); err != nil {
		return err
	}
	if username == "" {
		username = db.Admin.Username
	}

	admin, err := NewAdminCredential(username, password)
	if err != nil {
		return err
	}
	admin.LastPassword = time.Now()
	db.Admin = admin

	store := &Store{path: path, db: db}
	store.normalizeLocked()
	return store.saveLocked()
}

func (s *Store) SessionHours() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db.Options.SessionHours <= 0 {
		return 12
	}
	return s.db.Options.SessionHours
}

func (s *Store) ListInstances() []InstanceConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]InstanceConfig, len(s.db.Items))
	for i, item := range s.db.Items {
		out[i] = s.resolveConfigLocked(item)
	}
	return out
}

func (s *Store) GetInstance(id string) (InstanceConfig, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, item := range s.db.Items {
		if item.ID == id {
			return s.resolveConfigLocked(item), true
		}
	}
	return InstanceConfig{}, false
}

func (s *Store) RuntimeStatus(id string) (RuntimeStatus, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	st, ok := s.db.Runtime[id]
	if !ok || st.PublicAddress == "" || st.PublicPort == 0 {
		return RuntimeStatus{}, false
	}
	return RuntimeStatus{
		PublicAddress:     st.PublicAddress,
		PublicPort:        st.PublicPort,
		PublicStableSince: st.PublicStableSince,
		PublicUpdatedAt:   st.PublicUpdatedAt,
		PrivateAddress:    st.PrivateAddress,
		PrivatePort:       st.PrivatePort,
		Protocol:          st.Protocol,
	}, true
}

func (s *Store) SaveRuntimeStatus(id string, st RuntimeStatus) error {
	if id == "" || st.PublicAddress == "" || st.PublicPort == 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.db.Runtime == nil {
		s.db.Runtime = map[string]PersistedRuntimeStatus{}
	}
	next := PersistedRuntimeStatus{
		PublicAddress:     st.PublicAddress,
		PublicPort:        st.PublicPort,
		PublicStableSince: st.PublicStableSince,
		PublicUpdatedAt:   st.PublicUpdatedAt,
		PrivateAddress:    st.PrivateAddress,
		PrivatePort:       st.PrivatePort,
		Protocol:          st.Protocol,
	}
	if current, ok := s.db.Runtime[id]; ok && current == next {
		return nil
	}
	s.db.Runtime[id] = next
	return s.saveLocked()
}

func (s *Store) ClearRuntimeStatus(id string) error {
	if id == "" {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.db.Runtime[id]; !ok {
		return nil
	}
	delete(s.db.Runtime, id)
	return s.saveLocked()
}

func (s *Store) ServerGroups() ServerGroupsConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return ServerGroupsConfig{
		STUNServers: copyServerEndpoints(s.db.Options.STUNServers),
		HTTPServers: copyServerEndpoints(s.db.Options.HTTPServers),
		QUICServers: copyServerEndpoints(s.db.Options.QUICServers),
	}
}

func (s *Store) UpdateServerGroups(groups ServerGroupsConfig) (ServerGroupsConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	stunServers := groups.STUNServers
	if len(stunServers) == 0 && len(groups.STUNGroups) > 0 {
		stunServers = flattenLegacyServerGroups(groups.STUNGroups, defaultProbePort)
	}
	httpServers := groups.HTTPServers
	if len(httpServers) == 0 && len(groups.KeepAliveGroups) > 0 {
		httpServers = legacyKeepAliveServers(groups.KeepAliveGroups, false)
	}
	quicServers := groups.QUICServers
	if len(quicServers) == 0 && len(groups.KeepAliveGroups) > 0 {
		quicServers = legacyKeepAliveServers(groups.KeepAliveGroups, true)
	}

	stunServers = normalizeServerEndpoints(stunServers, defaultProbePort)
	httpServers = normalizeServerEndpoints(httpServers, 80)
	quicServers = normalizeServerEndpoints(quicServers, 443)
	if err := validateServerEndpoints(stunServers, "stun"); err != nil {
		return ServerGroupsConfig{}, err
	}
	if err := validateServerEndpoints(httpServers, "http"); err != nil {
		return ServerGroupsConfig{}, err
	}
	if err := validateServerEndpoints(quicServers, "quic"); err != nil {
		return ServerGroupsConfig{}, err
	}

	for _, item := range s.db.Items {
		normalizeConfig(&item)
		if err := validateConfig(item); err != nil {
			return ServerGroupsConfig{}, err
		}
		if item.STUNMode == "group" {
			if len(stunServers) == 0 {
				return ServerGroupsConfig{}, errors.New("stun server list is not available")
			}
		}
		if item.KeepAliveMode == "group" {
			if item.Protocol == "udp" && len(quicServers) == 0 {
				return ServerGroupsConfig{}, errors.New("quic server list is not available")
			}
			if item.Protocol != "udp" && len(httpServers) == 0 {
				return ServerGroupsConfig{}, errors.New("http server list is not available")
			}
		}
	}

	s.db.Options.STUNServers = stunServers
	s.db.Options.HTTPServers = httpServers
	s.db.Options.QUICServers = quicServers
	s.db.Options.STUNGroups = nil
	s.db.Options.KeepAliveGroups = nil
	if err := s.saveLocked(); err != nil {
		return ServerGroupsConfig{}, err
	}
	return ServerGroupsConfig{
		STUNServers: copyServerEndpoints(s.db.Options.STUNServers),
		HTTPServers: copyServerEndpoints(s.db.Options.HTTPServers),
		QUICServers: copyServerEndpoints(s.db.Options.QUICServers),
	}, nil
}

func (s *Store) AddInstance(cfg InstanceConfig) (InstanceConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if cfg.ID == "" {
		cfg.ID = newID()
	}
	normalizeConfig(&cfg)
	if err := s.validateConfigLocked(cfg); err != nil {
		return InstanceConfig{}, err
	}
	for _, item := range s.db.Items {
		if item.ID == cfg.ID {
			return InstanceConfig{}, fmt.Errorf("instance %s already exists", cfg.ID)
		}
	}

	s.db.Items = append(s.db.Items, cfg)
	if err := s.saveLocked(); err != nil {
		return InstanceConfig{}, err
	}
	return s.resolveConfigLocked(cfg), nil
}

func (s *Store) UpdateInstance(id string, cfg InstanceConfig) (InstanceConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cfg.ID = id
	normalizeConfig(&cfg)
	if err := s.validateConfigLocked(cfg); err != nil {
		return InstanceConfig{}, err
	}

	for i := range s.db.Items {
		if s.db.Items[i].ID == id {
			s.db.Items[i] = cfg
			if err := s.saveLocked(); err != nil {
				return InstanceConfig{}, err
			}
			return s.resolveConfigLocked(cfg), nil
		}
	}
	return InstanceConfig{}, os.ErrNotExist
}

func (s *Store) DeleteInstance(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.db.Items {
		if s.db.Items[i].ID == id {
			s.db.Items = append(s.db.Items[:i], s.db.Items[i+1:]...)
			delete(s.db.Runtime, id)
			return s.saveLocked()
		}
	}
	return os.ErrNotExist
}

func (s *Store) normalizeLocked() {
	if s.db.Version <= 0 {
		s.db.Version = 1
	}
	if s.db.Options.SessionHours <= 0 {
		s.db.Options.SessionHours = 12
	}
	if len(s.db.Options.STUNServers) == 0 {
		s.db.Options.STUNServers = flattenLegacyServerGroups(s.db.Options.STUNGroups, defaultProbePort)
	}
	if len(s.db.Options.STUNServers) == 0 {
		s.db.Options.STUNServers = defaultSTUNServers()
	}
	if len(s.db.Options.HTTPServers) == 0 {
		s.db.Options.HTTPServers = legacyKeepAliveServers(s.db.Options.KeepAliveGroups, false)
	}
	if len(s.db.Options.HTTPServers) == 0 {
		s.db.Options.HTTPServers = defaultHTTPServers()
	}
	if len(s.db.Options.QUICServers) == 0 {
		s.db.Options.QUICServers = legacyKeepAliveServers(s.db.Options.KeepAliveGroups, true)
	}
	if len(s.db.Options.QUICServers) == 0 {
		s.db.Options.QUICServers = defaultQUICServers()
	}
	s.db.Options.STUNServers = normalizeServerEndpoints(s.db.Options.STUNServers, defaultProbePort)
	s.db.Options.HTTPServers = normalizeServerEndpoints(s.db.Options.HTTPServers, 80)
	s.db.Options.QUICServers = normalizeServerEndpoints(s.db.Options.QUICServers, 443)
	s.db.Options.STUNGroups = nil
	s.db.Options.KeepAliveGroups = nil
	if s.db.Items == nil {
		s.db.Items = []InstanceConfig{}
	}
	if s.db.Runtime == nil {
		s.db.Runtime = map[string]PersistedRuntimeStatus{}
	}
	for i := range s.db.Items {
		normalizeConfig(&s.db.Items[i])
	}
}

func (s *Store) saveLocked() error {
	s.refreshAdminFromDiskLocked()

	dir := filepath.Dir(s.path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}

	raw, err := json.MarshalIndent(s.db, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')

	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *Store) refreshAdminFromDiskLocked() {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return
	}

	var disk Database
	if err := json.Unmarshal(raw, &disk); err != nil {
		return
	}
	if disk.Admin.Username == "" || disk.Admin.Salt == "" || disk.Admin.Hash == "" {
		return
	}
	if s.db.Admin.LastPassword.IsZero() || disk.Admin.LastPassword.After(s.db.Admin.LastPassword) {
		s.db.Admin = disk.Admin
	}
}

func (s *Store) validateConfigLocked(cfg InstanceConfig) error {
	if err := validateConfig(cfg); err != nil {
		return err
	}
	if cfg.STUNMode == "group" && len(s.db.Options.STUNServers) == 0 {
		return errors.New("stun server list is not available")
	}
	if cfg.KeepAliveMode == "group" {
		if cfg.Protocol == "udp" && len(s.db.Options.QUICServers) == 0 {
			return errors.New("quic server list is not available")
		}
		if cfg.Protocol != "udp" && len(s.db.Options.HTTPServers) == 0 {
			return errors.New("http server list is not available")
		}
	}
	return nil
}

func (s *Store) resolveConfigLocked(cfg InstanceConfig) InstanceConfig {
	normalizeConfig(&cfg)
	if cfg.STUNMode == "group" {
		cfg.resolvedSTUNServers = copyServerEndpoints(s.db.Options.STUNServers)
	}
	if cfg.KeepAliveMode == "group" {
		if cfg.Protocol == "udp" {
			cfg.resolvedKeepAliveServers = copyServerEndpoints(s.db.Options.QUICServers)
		} else {
			cfg.resolvedKeepAliveServers = copyServerEndpoints(s.db.Options.HTTPServers)
		}
	}
	return cfg
}

func copyServerEndpoints(servers []ServerEndpoint) []ServerEndpoint {
	out := make([]ServerEndpoint, len(servers))
	copy(out, servers)
	return out
}

func flattenLegacyServerGroups(groups []ServerGroup, defaultPort int) []ServerEndpoint {
	out := []ServerEndpoint{}
	for _, group := range groups {
		out = append(out, normalizeServerEndpoints(group.Servers, defaultPort)...)
	}
	return normalizeServerEndpoints(out, defaultPort)
}

func legacyKeepAliveServers(groups []ServerGroup, quic bool) []ServerEndpoint {
	out := []ServerEndpoint{}
	defaultPort := 80
	if quic {
		defaultPort = 443
	}
	for _, group := range groups {
		key := strings.ToLower(group.ID + " " + group.Name)
		if quic {
			if !strings.Contains(key, "quic") && !strings.Contains(key, "udp") {
				continue
			}
			out = append(out, normalizeServerEndpoints(group.Servers, defaultPort)...)
			continue
		}
		if strings.Contains(key, "quic") || strings.Contains(key, "udp") {
			continue
		}
		out = append(out, normalizeServerEndpoints(group.Servers, defaultPort)...)
	}
	return normalizeServerEndpoints(out, defaultPort)
}
