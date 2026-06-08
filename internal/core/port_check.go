package core

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"
)

var errNoTCPMapping = errors.New("tcp public mapping is not ready")

func (m *Manager) CheckTCPPort(ctx context.Context, id string) (PortCheck, error) {
	m.mu.RLock()
	cfg, cfgOK := m.store.GetInstance(id)
	st := m.statusForLocked(id)
	m.mu.RUnlock()
	if !cfgOK {
		return PortCheck{}, os.ErrNotExist
	}
	if cfg.Protocol != "tcp" {
		return PortCheck{}, errors.New("only tcp reachability check is supported")
	}
	if st.PublicAddress == "" || st.PublicPort <= 0 {
		check := PortCheck{
			Protocol:  "tcp",
			State:     "unknown",
			CheckedAt: time.Now(),
			Message:   errNoTCPMapping.Error(),
		}
		m.report(id, RuntimeStatus{PortCheck: check})
		return check, nil
	}

	target := net.JoinHostPort(st.PublicAddress, fmt.Sprint(st.PublicPort))
	started := time.Now()
	dialer := net.Dialer{
		Timeout: 2500 * time.Millisecond,
		Control: socketControl(cfg.Interface, cfg.FWMark),
	}
	conn, err := dialer.DialContext(ctx, "tcp4", target)
	checkedAt := time.Now()
	check := PortCheck{
		Protocol:  "tcp",
		CheckedAt: checkedAt,
	}
	if err != nil {
		check.State = classifyTCPCheckError(err)
		check.Message = err.Error()
		m.report(id, RuntimeStatus{PortCheck: check})
		return check, nil
	}
	_ = conn.Close()
	check.State = "open"
	check.LatencyMs = maxInt64(1, time.Since(started).Milliseconds())
	check.Message = "tcp connect succeeded from NATCat host"
	m.report(id, RuntimeStatus{PortCheck: check})
	return check, nil
}

func classifyTCPCheckError(err error) string {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return "timeout"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	return "closed"
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
