package cloudserver

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

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

func TestPrivateModeConfigRejectsUnknownMode(t *testing.T) {
	t.Setenv("CODELOCAL_PRIVATE_MODE", "maybe")
	t.Setenv("CODELOCAL_OWNER_EMAIL", "owner@example.com")
	t.Setenv("CODELOCAL_OWNER_PASSWORD", "a-strong-private-password")

	if _, err := privateModeConfigFromEnv(); err == nil {
		t.Fatal("expected unknown private mode value to fail closed")
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

func TestPrivateModeSignupGuardBlocksSignupAndInviteButAllowsLogin(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})
	handler := privateModeSignupGuard(next)

	for _, path := range []string{"/signup", "/signup/verify", "/api/v1/auth/signup-verification", "/api/v1/invite"} {
		called = false
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, path, nil))
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("%s status=%d, want %d", path, recorder.Code, http.StatusNotFound)
		}
		if called {
			t.Fatalf("%s reached the wrapped handler", path)
		}
	}

	called = false
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/login", nil))
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("login status=%d, want %d", recorder.Code, http.StatusNoContent)
	}
	if !called {
		t.Fatal("login should reach the wrapped handler")
	}
}
