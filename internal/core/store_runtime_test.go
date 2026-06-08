package core

import (
	"path/filepath"
	"testing"
	"time"
)

func TestStorePersistsRuntimeStatus(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data.json")
	store, _, err := OpenStore(path, "admin", "test-password")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	cfg, err := store.AddInstance(InstanceConfig{
		Name:             "Runtime",
		Protocol:         "tcp",
		BindPort:         "200",
		KeepAliveSeconds: 30,
		HTTPHost:         "qq.com",
		HTTPPort:         80,
	})
	if err != nil {
		t.Fatalf("add instance: %v", err)
	}

	updatedAt := time.Date(2026, 6, 7, 16, 0, 0, 0, time.Local)
	if err := store.SaveRuntimeStatus(cfg.ID, RuntimeStatus{
		PublicAddress:     "203.0.113.8",
		PublicPort:        5000,
		PublicStableSince: updatedAt.Add(-time.Minute),
		PublicUpdatedAt:   updatedAt,
		PrivateAddress:    "192.168.1.10",
		PrivatePort:       200,
		Protocol:          "tcp",
	}); err != nil {
		t.Fatalf("save runtime: %v", err)
	}

	reopened, _, err := OpenStore(path, "admin", "unused")
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	got, ok := reopened.RuntimeStatus(cfg.ID)
	if !ok {
		t.Fatal("runtime status missing after reopen")
	}
	if got.PublicAddress != "203.0.113.8" || got.PublicPort != 5000 {
		t.Fatalf("public mapping = %s:%d, want 203.0.113.8:5000", got.PublicAddress, got.PublicPort)
	}
	if !got.PublicUpdatedAt.Equal(updatedAt) {
		t.Fatalf("public updated at = %s, want %s", got.PublicUpdatedAt, updatedAt)
	}
}

func TestStoreClearsRuntimeStatus(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data.json")
	store, _, err := OpenStore(path, "admin", "test-password")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	cfg, err := store.AddInstance(InstanceConfig{
		Name:             "Runtime Clear",
		Protocol:         "tcp",
		BindPort:         "200",
		KeepAliveSeconds: 30,
		HTTPHost:         "qq.com",
		HTTPPort:         80,
	})
	if err != nil {
		t.Fatalf("add instance: %v", err)
	}
	if err := store.SaveRuntimeStatus(cfg.ID, RuntimeStatus{
		PublicAddress:  "203.0.113.8",
		PublicPort:     5000,
		PrivateAddress: "192.168.1.10",
		PrivatePort:    200,
		Protocol:       "tcp",
	}); err != nil {
		t.Fatalf("save runtime: %v", err)
	}
	if err := store.ClearRuntimeStatus(cfg.ID); err != nil {
		t.Fatalf("clear runtime: %v", err)
	}

	reopened, _, err := OpenStore(path, "admin", "unused")
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	if got, ok := reopened.RuntimeStatus(cfg.ID); ok {
		t.Fatalf("runtime status still present after clear: %#v", got)
	}
}

func TestStoreDefaultsMappingConfirmations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data.json")
	store, _, err := OpenStore(path, "admin", "test-password")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	cfg, err := store.AddInstance(InstanceConfig{
		Name:             "Confirmations",
		Protocol:         "tcp",
		BindPort:         "200",
		KeepAliveSeconds: 30,
		HTTPHost:         "qq.com",
		HTTPPort:         80,
	})
	if err != nil {
		t.Fatalf("add instance: %v", err)
	}
	if cfg.MappingConfirmations != defaultMappingConfirmations {
		t.Fatalf("mapping confirmations = %d, want %d", cfg.MappingConfirmations, defaultMappingConfirmations)
	}
}

func TestStoreRejectsInvalidMappingConfirmations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data.json")
	store, _, err := OpenStore(path, "admin", "test-password")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	_, err = store.AddInstance(InstanceConfig{
		Name:                 "Confirmations",
		Protocol:             "tcp",
		BindPort:             "200",
		KeepAliveSeconds:     30,
		MappingConfirmations: maxMappingConfirmations + 1,
		HTTPHost:             "qq.com",
		HTTPPort:             80,
	})
	if err == nil {
		t.Fatal("invalid mapping confirmations was accepted")
	}
}

func TestChangeAdminPassword(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data.json")
	store, _, err := OpenStore(path, "admin", "old-password")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	if err := ChangeAdminPassword(path, "", "new-password"); err != nil {
		t.Fatalf("change password: %v", err)
	}

	runningAdmin := store.Admin()
	if CheckPassword(runningAdmin, "admin", "old-password") {
		t.Fatal("running store still accepts old password")
	}
	if !CheckPassword(runningAdmin, "admin", "new-password") {
		t.Fatal("running store does not accept new password")
	}
	if err := store.SaveRuntimeStatus("test-instance", RuntimeStatus{
		PublicAddress: "203.0.113.8",
		PublicPort:    5000,
	}); err != nil {
		t.Fatalf("save runtime after password change: %v", err)
	}

	reopened, _, err := OpenStore(path, "admin", "unused")
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	admin := reopened.Admin()
	if CheckPassword(admin, "admin", "old-password") {
		t.Fatal("old password still works")
	}
	if !CheckPassword(admin, "admin", "new-password") {
		t.Fatal("new password does not work")
	}
	if admin.LastPassword.IsZero() {
		t.Fatal("last password timestamp was not updated")
	}
}
