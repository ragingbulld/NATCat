package core

import (
	"testing"
	"time"
)

func TestManagerClearsKeepAliveOnLifecycleStart(t *testing.T) {
	m := NewManager(nil)
	id := "instance-1"
	started := time.Now().Add(-time.Minute)
	m.status[id] = RuntimeStatus{
		State:     StateStopped,
		StartedAt: &started,
		KeepAlive: KeepAlive{
			State:       KeepAliveConnected,
			Protocol:    "tcp",
			Address:     "203.0.113.1",
			Port:        80,
			ConnectedAt: started,
		},
	}

	m.setStatusLocked(id, StateStarting, "", nil)

	got := m.status[id]
	if got.KeepAlive.State != "" || !got.KeepAlive.ConnectedAt.IsZero() {
		t.Fatalf("keepalive after start = %#v, want cleared", got.KeepAlive)
	}
}

func TestManagerClearsKeepAliveOnLifecycleReport(t *testing.T) {
	m := NewManager(nil)
	id := "instance-1"
	started := time.Now().Add(-time.Minute)
	m.status[id] = RuntimeStatus{
		State:     StateRunning,
		StartedAt: &started,
		KeepAlive: KeepAlive{
			State:       KeepAliveConnected,
			Protocol:    "tcp",
			Address:     "203.0.113.1",
			Port:        80,
			ConnectedAt: started,
		},
	}

	m.report(id, RuntimeStatus{State: StateStopped})

	got := m.status[id]
	if got.KeepAlive.State != "" || !got.KeepAlive.ConnectedAt.IsZero() {
		t.Fatalf("keepalive after lifecycle report = %#v, want cleared", got.KeepAlive)
	}
}

func TestManagerClearsKeepAliveOnFreshRunnerStart(t *testing.T) {
	m := NewManager(nil)
	id := "instance-1"
	previous := time.Now().Add(-time.Minute)
	started := time.Now()
	m.status[id] = RuntimeStatus{
		State: StateStopped,
		KeepAlive: KeepAlive{
			State:       KeepAliveConnected,
			Protocol:    "tcp",
			Address:     "203.0.113.1",
			Port:        80,
			ConnectedAt: previous,
		},
	}

	m.report(id, RuntimeStatus{State: StateStarting, StartedAt: &started})

	got := m.status[id]
	if got.KeepAlive.State != "" || !got.KeepAlive.ConnectedAt.IsZero() {
		t.Fatalf("keepalive after fresh runner start = %#v, want cleared", got.KeepAlive)
	}
}

func TestManagerPreservesKeepAliveDuringReconnectStatusLogs(t *testing.T) {
	m := NewManager(nil)
	id := "instance-1"
	started := time.Now().Add(-time.Minute)
	m.status[id] = RuntimeStatus{
		State:     StateRunning,
		StartedAt: &started,
		KeepAlive: KeepAlive{
			State:      KeepAliveReconnecting,
			Protocol:   "tcp",
			Address:    "203.0.113.1",
			Port:       80,
			LastSeenAt: time.Now(),
			Message:    "session closed",
		},
	}

	m.report(id, RuntimeStatus{
		State: StateStarting,
		Logs:  []LogEntry{{At: time.Now(), Level: "info", Message: "$ keepalive reconnect --proto tcp --attempt 1"}},
	})

	got := m.status[id].KeepAlive
	if got.State != KeepAliveReconnecting {
		t.Fatalf("keepalive state = %q, want reconnecting", got.State)
	}
}

func TestManagerIgnoresLateKeepAliveAfterStop(t *testing.T) {
	m := NewManager(nil)
	id := "instance-1"
	m.status[id] = RuntimeStatus{State: StateStopping}

	m.report(id, RuntimeStatus{
		KeepAlive: KeepAlive{
			State:       KeepAliveConnected,
			Protocol:    "tcp",
			Address:     "203.0.113.1",
			Port:        80,
			ConnectedAt: time.Now(),
		},
	})

	got := m.status[id]
	if got.KeepAlive.State != "" {
		t.Fatalf("late keepalive after stop = %#v, want ignored", got.KeepAlive)
	}
}

func TestManagerDoesNotPreserveConnectedAtFromPreviousRun(t *testing.T) {
	m := NewManager(nil)
	id := "instance-1"
	started := time.Now()
	previous := started.Add(-20 * time.Second)
	current := started.Add(time.Second)
	m.status[id] = RuntimeStatus{
		State:     StateStarting,
		StartedAt: &started,
		KeepAlive: KeepAlive{
			State:       KeepAliveConnected,
			Protocol:    "tcp",
			Address:     "203.0.113.1",
			Port:        80,
			ConnectedAt: previous,
		},
	}

	m.report(id, RuntimeStatus{
		KeepAlive: KeepAlive{
			State:       KeepAliveConnected,
			Protocol:    "tcp",
			Address:     "203.0.113.1",
			Port:        80,
			ConnectedAt: current,
		},
	})

	got := m.status[id].KeepAlive.ConnectedAt
	if !got.Equal(current) {
		t.Fatalf("connectedAt = %s, want current run time %s", got, current)
	}
}

func TestRuntimeWithServerAgesUsesServerClock(t *testing.T) {
	connectedAt := time.Date(2026, 6, 11, 14, 0, 0, 0, time.UTC)
	st := RuntimeStatus{
		KeepAlive: KeepAlive{
			State:       KeepAliveConnected,
			ConnectedAt: connectedAt,
		},
	}

	got := runtimeWithServerAges(st, connectedAt.Add(20*time.Second)).KeepAlive.ConnectedSeconds
	if got != 20 {
		t.Fatalf("connectedSeconds = %d, want 20", got)
	}
}

func TestKeepAliveAgesReportsServerSeconds(t *testing.T) {
	m := NewManager(nil)
	id := "instance-1"
	m.status[id] = RuntimeStatus{
		KeepAlive: KeepAlive{
			State:       KeepAliveConnected,
			ConnectedAt: time.Now().Add(-3 * time.Second),
		},
	}

	ages := m.KeepAliveAges()
	if len(ages) != 1 {
		t.Fatalf("age events = %d, want 1", len(ages))
	}
	if ages[0].ID != id {
		t.Fatalf("age id = %q, want %q", ages[0].ID, id)
	}
	if ages[0].ConnectedSeconds < 2 || ages[0].ConnectedSeconds > 4 {
		t.Fatalf("connectedSeconds = %d, want around 3", ages[0].ConnectedSeconds)
	}
}

func TestManagerPreservesConnectedAtWithinSameRun(t *testing.T) {
	m := NewManager(nil)
	id := "instance-1"
	started := time.Now()
	first := started.Add(time.Second)
	refresh := started.Add(30 * time.Second)
	m.status[id] = RuntimeStatus{
		State:     StateStarting,
		StartedAt: &started,
		KeepAlive: KeepAlive{
			State:       KeepAliveConnected,
			Protocol:    "tcp",
			Address:     "203.0.113.1",
			Port:        80,
			ConnectedAt: first,
		},
	}

	m.report(id, RuntimeStatus{
		KeepAlive: KeepAlive{
			State:       KeepAliveConnected,
			Protocol:    "tcp",
			Address:     "203.0.113.1",
			Port:        80,
			ConnectedAt: refresh,
		},
	})

	got := m.status[id].KeepAlive.ConnectedAt
	if !got.Equal(first) {
		t.Fatalf("connectedAt = %s, want first connection time %s", got, first)
	}
}
