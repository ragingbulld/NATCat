package core

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestNotifyScriptIsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hook.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o600); err != nil {
		t.Fatalf("write temp script: %v", err)
	}

	if !notifyScriptIsFile(path) {
		t.Fatalf("expected %q to be detected as a file", path)
	}
	if notifyScriptIsFile("echo hello") {
		t.Fatal("inline command should not be detected as a file")
	}
	if notifyScriptIsFile("echo hello\nexit 0") {
		t.Fatal("multiline script should not be detected as a file")
	}
}

func TestNotifyEnvIncludesPublicMappingVars(t *testing.T) {
	cfg := InstanceConfig{
		ID:   "abc123",
		Name: "Hook Test",
	}
	event := mappingEvent{
		PublicIP:    mustParseIP(t, "203.0.113.8"),
		PublicPort:  5000,
		PrivateIP:   mustParseIP(t, "192.168.1.10"),
		PrivatePort: 3000,
		Protocol:    "tcp",
	}

	env := notifyEnv(cfg, event)
	lookup := map[string]string{}
	for _, entry := range env {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		lookup[key] = value
	}

	want := map[string]string{
		"NATCAT_INSTANCE_ID":     "abc123",
		"NATCAT_INSTANCE_NAME":   "Hook Test",
		"NATCAT_PROTOCOL":        "tcp",
		"NATCAT_PUBLIC_ADDRESS":  "203.0.113.8",
		"NATCAT_PUBLIC_IP":       "203.0.113.8",
		"NATCAT_PUBLIC_PORT":     "5000",
		"NATCAT_PUBLIC_ENDPOINT": "203.0.113.8:5000",
		"NATCAT_PRIVATE_ADDRESS": "192.168.1.10",
		"NATCAT_PRIVATE_PORT":    "3000",
	}
	for key, value := range want {
		if got := lookup[key]; got != value {
			t.Fatalf("%s = %q, want %q", key, got, value)
		}
	}
}

func TestExpandNotifyScriptReplacesPublicTemplateVars(t *testing.T) {
	event := mappingEvent{
		PublicIP:    mustParseIP(t, "203.0.113.8"),
		PublicPort:  5000,
		PrivateIP:   mustParseIP(t, "192.168.1.10"),
		PrivatePort: 3000,
		Protocol:    "tcp",
	}

	script := `echo $NATCAT_PUBLIC_IP ${NATCAT_PUBLIC_PORT} "$NATCAT_PUBLIC_ENDPOINT" "$HOME" "$NATCAT_PUBLIC_ENDPOINT_EXTRA" "$NATCAT_INSTANCE_NAME"`
	got := expandNotifyScript(script, notifyTemplateVars(event))
	want := `echo 203.0.113.8 5000 "203.0.113.8:5000" "$HOME" "$NATCAT_PUBLIC_ENDPOINT_EXTRA" "$NATCAT_INSTANCE_NAME"`
	if got != want {
		t.Fatalf("expanded script = %q, want %q", got, want)
	}
}

func TestNotifyCommandDoesNotInjectLegacyArgs(t *testing.T) {
	cmd := notifyCommand("echo hello")
	var want []string
	if runtime.GOOS == "windows" {
		want = []string{"powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "echo hello"}
	} else {
		want = []string{"sh", "-c", "echo hello"}
	}
	if !reflect.DeepEqual(cmd.Args, want) {
		t.Fatalf("command args = %v, want %v", cmd.Args, want)
	}
}

func TestRunNotifyScriptTestUsesCurrentMappingAndCapturesOutput(t *testing.T) {
	cfg := InstanceConfig{
		ID:   "abc123",
		Name: "Hook Test",
	}
	st := RuntimeStatus{
		PublicAddress:  "203.0.113.8",
		PublicPort:     5000,
		PrivateAddress: "192.168.1.10",
		PrivatePort:    3000,
		Protocol:       "tcp",
	}
	script := `echo "$NATCAT_PUBLIC_IP $NATCAT_PUBLIC_PORT $NATCAT_PUBLIC_ENDPOINT"`
	if runtime.GOOS == "windows" {
		script = `Write-Output "$NATCAT_PUBLIC_IP $NATCAT_PUBLIC_PORT $NATCAT_PUBLIC_ENDPOINT"`
	}
	result, err := RunNotifyScriptTest(context.Background(), cfg, st, script)
	if err != nil {
		t.Fatalf("run notify script test: %v", err)
	}
	if !result.OK || result.ExitCode != 0 {
		t.Fatalf("result ok=%v exit=%d", result.OK, result.ExitCode)
	}
	gotOutput := strings.Join(strings.Fields(result.Output), " ")
	if !strings.Contains(gotOutput, "203.0.113.8 5000 203.0.113.8:5000") {
		t.Fatalf("output = %q, want current mapping values", result.Output)
	}
}

func mustParseIP(t *testing.T, value string) net.IP {
	t.Helper()
	ip := net.ParseIP(value)
	if ip == nil {
		t.Fatalf("parse ip %q", value)
	}
	return ip
}
