package cloudserver

import "testing"

func TestPrivateModeConfigDisabledByDefault(t *testing.T) {
	t.Setenv("CODELOCAL_PRIVATE_MODE", "")
	t.Setenv("CODELOCAL_OWNER_EMAIL", "")
	t.Setenv("CODELOCAL_OWNER_PASSWORD", "")

	cfg, err := privateModeConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Enabled {
		t.Fatal("private mode must be disabled by default")
	}
}

func TestPrivateModeConfigRequiresOwnerCredentials(t *testing.T) {
	t.Setenv("CODELOCAL_PRIVATE_MODE", "1")
	t.Setenv("CODELOCAL_OWNER_EMAIL", "owner@example.com")
	t.Setenv("CODELOCAL_OWNER_PASSWORD", "")

	if _, err := privateModeConfigFromEnv(); err == nil {
		t.Fatal("expected missing owner password to fail closed")
	}
}

func TestPrivateModeConfigLoadsSingleOwner(t *testing.T) {
	t.Setenv("CODELOCAL_PRIVATE_MODE", "true")
	t.Setenv("CODELOCAL_OWNER_EMAIL", " Owner@Example.com ")
	t.Setenv("CODELOCAL_OWNER_PASSWORD", "a-strong-private-password")

	cfg, err := privateModeConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Enabled {
		t.Fatal("private mode should be enabled")
	}
	if cfg.OwnerEmail != "owner@example.com" {
		t.Fatalf("owner email=%q, want %q", cfg.OwnerEmail, "owner@example.com")
	}
	if cfg.OwnerPassword != "a-strong-private-password" {
		t.Fatal("owner password was not loaded")
	}
}
