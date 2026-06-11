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
