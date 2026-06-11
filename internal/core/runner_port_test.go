package core

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestRunnerBindPortZeroSticksToActualPort(t *testing.T) {
	r := NewRunner(InstanceConfig{BindPort: "0"}, nil)

	if got := r.bindPort(); got != 0 {
		t.Fatalf("initial dynamic bind port = %d, want 0", got)
	}

	r.keepBindPort(41234)
	if got := r.bindPort(); got != 41234 {
		t.Fatalf("sticky dynamic bind port = %d, want actual port 41234", got)
	}

	r.keepBindPort(41234)
	if got := r.bindPort(); got != 41234 {
		t.Fatalf("bind port changed without advance = %d, want 41234", got)
	}

	r.advanceBindPort()
	if got := r.bindPort(); got != 0 {
		t.Fatalf("advanced dynamic bind port = %d, want 0 for OS repick", got)
	}
}

func TestRunnerRangeBindPortOnlyAdvancesWhenRequested(t *testing.T) {
	r := NewRunner(InstanceConfig{BindPort: "100-101"}, nil)

	if got := r.bindPort(); got != 100 {
		t.Fatalf("initial range bind port = %d, want 100", got)
	}

	r.keepBindPort(100)
	if got := r.bindPort(); got != 100 {
		t.Fatalf("range bind port changed without advance = %d, want 100", got)
	}

	r.advanceBindPort()
	if got := r.bindPort(); got != 101 {
		t.Fatalf("advanced range bind port = %d, want 101", got)
	}
}

func TestRunnerRandomRangeSkipsFailedPortWhenPossible(t *testing.T) {
	r := NewRunner(InstanceConfig{BindPort: "100~101"}, nil)

	first := r.bindPort()
	r.advanceBindPort()
	next := r.bindPort()

	if next == first {
		t.Fatalf("advanced random range repeated failed port %d", first)
	}
}

func TestLocalPortUnavailableClassification(t *testing.T) {
	if !isLocalPortUnavailable(errors.New("bind: address already in use")) {
		t.Fatal("address already in use should be a local port unavailable error")
	}
	if !isLocalPortUnavailable(errors.New("connectex: Only one usage of each socket address (protocol/network address/port) is normally permitted.")) {
		t.Fatal("Windows socket-address-in-use error should be a local port unavailable error")
	}
	if !isLocalPortUnavailable(errors.New("bind: An attempt was made to access a socket in a way forbidden by its access permissions.")) {
		t.Fatal("Windows access-permissions bind error should be a local port unavailable error")
	}
	if isLocalPortUnavailable(errors.New("connect: connection refused")) {
		t.Fatal("remote connection failure should not advance bind port")
	}
	if isLocalPortUnavailable(errors.New("cannot assign requested address")) {
		t.Fatal("invalid local address should not be treated as a port rotation signal")
	}
}

func TestRunnerSeedRuntimePreservesPublicUpdatedAtWhenPublicMappingIsSame(t *testing.T) {
	updatedAt := time.Date(2026, 6, 7, 15, 0, 0, 0, time.Local)
	stableSince := updatedAt.Add(-10 * time.Minute)
	r := NewRunner(InstanceConfig{Protocol: "tcp"}, nil)
	r.seedRuntime(RuntimeStatus{
		PublicAddress:     "203.0.113.8",
		PublicPort:        5000,
		PublicStableSince: stableSince,
		PublicUpdatedAt:   updatedAt,
		PrivateAddress:    "192.168.1.10",
		PrivatePort:       200,
		Protocol:          "tcp",
	})

	changed, gotStableSince, gotUpdatedAt := r.updateMapping(mappingEvent{
		PublicIP:    net.ParseIP("203.0.113.8"),
		PublicPort:  5000,
		PrivateIP:   net.ParseIP("192.168.1.10"),
		PrivatePort: 200,
		Protocol:    "tcp",
	})

	if changed {
		t.Fatal("same mapping after restart should not be treated as changed")
	}
	if !gotStableSince.Equal(stableSince) {
		t.Fatalf("stable since = %s, want %s", gotStableSince, stableSince)
	}
	if !gotUpdatedAt.Equal(updatedAt) {
		t.Fatalf("updated at = %s, want %s", gotUpdatedAt, updatedAt)
	}
}

func TestRunnerSeedRuntimeRefreshesPublicUpdatedAtWhenPublicMappingChanges(t *testing.T) {
	updatedAt := time.Now().Add(-time.Hour)
	r := NewRunner(InstanceConfig{Protocol: "tcp"}, nil)
	r.seedRuntime(RuntimeStatus{
		PublicAddress:     "203.0.113.8",
		PublicPort:        5000,
		PublicStableSince: updatedAt,
		PublicUpdatedAt:   updatedAt,
		PrivateAddress:    "192.168.1.10",
		PrivatePort:       200,
		Protocol:          "tcp",
	})

	changed, _, gotUpdatedAt := r.updateMapping(mappingEvent{
		PublicIP:    net.ParseIP("203.0.113.8"),
		PublicPort:  5001,
		PrivateIP:   net.ParseIP("192.168.1.10"),
		PrivatePort: 200,
		Protocol:    "tcp",
	})

	if !changed {
		t.Fatal("changed public port should be treated as changed")
	}
	if !gotUpdatedAt.After(updatedAt) {
		t.Fatalf("updated at = %s, want after %s", gotUpdatedAt, updatedAt)
	}
}

func TestRunnerPublishMappingEmitsMappedLogOnceAfterSeededRestart(t *testing.T) {
	r := NewRunner(InstanceConfig{Protocol: "tcp"}, nil)
	r.seedRuntime(RuntimeStatus{
		PublicAddress:     "203.0.113.8",
		PublicPort:        5000,
		PublicStableSince: time.Date(2026, 6, 7, 15, 0, 0, 0, time.Local),
		PublicUpdatedAt:   time.Date(2026, 6, 7, 15, 0, 0, 0, time.Local),
		PrivateAddress:    "192.168.1.10",
		PrivatePort:       200,
		Protocol:          "tcp",
	})

	var updates []RuntimeStatus
	r.report = func(_ string, update RuntimeStatus) {
		updates = append(updates, update)
	}

	event := mappingEvent{
		PublicIP:    net.ParseIP("203.0.113.8"),
		PublicPort:  5000,
		PrivateIP:   net.ParseIP("192.168.1.10"),
		PrivatePort: 200,
		Protocol:    "tcp",
	}
	r.publishMapping(event)
	r.publishMapping(event)

	if len(updates) != 2 {
		t.Fatalf("got %d runtime updates, want 2", len(updates))
	}
	if len(updates[0].Logs) != 1 || updates[0].Logs[0].Message != "mapped 203.0.113.8:5000 -> 192.168.1.10:200" {
		t.Fatalf("first publish logs = %#v, want mapped log", updates[0].Logs)
	}
	if len(updates[1].Logs) != 0 {
		t.Fatalf("second publish logs = %#v, want none", updates[1].Logs)
	}
}

func TestRunnerConfirmPublicProbeRequiresConsecutiveMatches(t *testing.T) {
	oldDelay := publicProbeConfirmDelay
	publicProbeConfirmDelay = time.Nanosecond
	defer func() {
		publicProbeConfirmDelay = oldDelay
	}()

	r := NewRunner(InstanceConfig{MappingConfirmations: 3}, nil)
	results := []stunResult{
		stunTestResult("203.0.113.8", 5000),
		stunTestResult("188.40.203.74", 40403),
		stunTestResult("203.0.113.8", 5000),
		stunTestResult("203.0.113.8", 5000),
		stunTestResult("203.0.113.8", 5000),
	}
	calls := 0

	got, err := r.confirmPublicProbe(context.Background(), 2, func() (stunResult, error) {
		if calls >= len(results) {
			t.Fatalf("probe called too many times: %d", calls+1)
		}
		result := results[calls]
		calls++
		return result, nil
	})
	if err != nil {
		t.Fatalf("confirm public probe: %v", err)
	}
	if calls != 5 {
		t.Fatalf("probe calls = %d, want 5", calls)
	}
	if !samePublicProbeResult(got, stunTestResult("203.0.113.8", 5000)) {
		t.Fatalf("confirmed result = %s, want 203.0.113.8:5000", formatPublicProbeResult(got))
	}
}

func TestRunnerConfirmPublicProbeSingleConfirmationUsesOneProbe(t *testing.T) {
	r := NewRunner(InstanceConfig{MappingConfirmations: 1}, nil)
	calls := 0

	got, err := r.confirmPublicProbe(context.Background(), 1, func() (stunResult, error) {
		calls++
		return stunTestResult("203.0.113.8", 5000), nil
	})
	if err != nil {
		t.Fatalf("confirm public probe: %v", err)
	}
	if calls != 1 {
		t.Fatalf("probe calls = %d, want 1", calls)
	}
	if !samePublicProbeResult(got, stunTestResult("203.0.113.8", 5000)) {
		t.Fatalf("confirmed result = %s, want 203.0.113.8:5000", formatPublicProbeResult(got))
	}
}

func TestRunnerConfirmPublicProbeKeepsProgressAcrossRoundFailures(t *testing.T) {
	oldDelay := publicProbeConfirmDelay
	publicProbeConfirmDelay = time.Nanosecond
	defer func() {
		publicProbeConfirmDelay = oldDelay
	}()

	r := NewRunner(InstanceConfig{MappingConfirmations: 2}, nil)
	progress := &publicProbeConfirmationProgress{}
	calls := 0

	_, err := r.confirmPublicProbeWithProgress(context.Background(), 4, progress, func() (stunResult, error) {
		calls++
		if calls == 1 {
			return stunTestResult("203.0.113.8", 5000), nil
		}
		return stunResult{}, fmt.Errorf("%w: first batch failed", errPublicProbeRoundFailed)
	})
	if !errors.Is(err, errPublicProbeRoundFailed) {
		t.Fatalf("confirm error = %v, want errPublicProbeRoundFailed", err)
	}
	if progress.count != 1 || !samePublicProbeResult(progress.candidate, stunTestResult("203.0.113.8", 5000)) {
		t.Fatalf("progress = %#v, want 203.0.113.8:5000 confirmed once", progress)
	}

	got, err := r.confirmPublicProbeWithProgress(context.Background(), 4, progress, func() (stunResult, error) {
		calls++
		return stunTestResult("203.0.113.8", 5000), nil
	})
	if err != nil {
		t.Fatalf("confirm public probe retry: %v", err)
	}
	if calls != 3 {
		t.Fatalf("probe calls = %d, want 3", calls)
	}
	if !samePublicProbeResult(got, stunTestResult("203.0.113.8", 5000)) {
		t.Fatalf("confirmed result = %s, want 203.0.113.8:5000", formatPublicProbeResult(got))
	}
	if progress.count != 0 {
		t.Fatalf("progress count after success = %d, want 0", progress.count)
	}
}

func stunTestResult(ip string, port int) stunResult {
	return stunResult{IP: net.ParseIP(ip), Port: port}
}
