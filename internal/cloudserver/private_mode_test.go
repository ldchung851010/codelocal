package cloudserver

import (
	"net/http"
	"net/http/httptest"
	"os"
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

func TestPrivateModeConfigRejectsInvalidOwnerEmail(t *testing.T) {
	t.Setenv("CODELOCAL_PRIVATE_MODE", "1")
	t.Setenv("CODELOCAL_OWNER_EMAIL", "not-an-email")
	t.Setenv("CODELOCAL_OWNER_PASSWORD", "a-strong-private-password")

	if _, err := privateModeConfigFromEnv(); err == nil {
		t.Fatal("expected invalid owner email to fail closed")
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

func TestEnsurePrivateOwnerAdminDefaultsToOwner(t *testing.T) {
	t.Setenv("CODELOCAL_ADMIN_EMAILS", "")
	t.Setenv("CODELOCAL_ADMIN_EMAIL", "")

	if err := ensurePrivateOwnerAdmin("owner@example.com"); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("CODELOCAL_ADMIN_EMAIL"); got != "owner@example.com" {
		t.Fatalf("CODELOCAL_ADMIN_EMAIL=%q, want %q", got, "owner@example.com")
	}
}

func TestEnsurePrivateOwnerAdminRejectsExplicitMismatch(t *testing.T) {
	t.Setenv("CODELOCAL_ADMIN_EMAILS", "someone@example.com")
	t.Setenv("CODELOCAL_ADMIN_EMAIL", "")

	if err := ensurePrivateOwnerAdmin("owner@example.com"); err == nil {
		t.Fatal("expected explicit admin list without owner to fail closed")
	}
}

func TestPrivateModeSignupGuardBlocksSignupAndInviteSurfaces(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})
	handler := privateModeSignupGuard(next)

	blocked := []string{
		"/signup",
		"/signup/",
		"/signup/verify",
		"/signup/verify/anything",
		"/invite",
		"/invite/foo",
		"/api/v1/auth/signup-verification",
		"/api/v1/invite",
		"/api/v1/invite/foo",
	}
	for _, path := range blocked {
		called = false
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, path, nil))
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("%s status=%d, want %d", path, recorder.Code, http.StatusNotFound)
		}
		if called {
			t.Fatalf("%s reached the wrapped handler", path)
		}
		if recorder.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s must disable caching", path)
		}
	}
}

func TestPrivateModeSignupGuardAllowsLoginPairingAndNearMisses(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})
	handler := privateModeSignupGuard(next)

	allowed := []string{"/login", "/pair/start", "/signup-help", "/invitee", "/api/v1/invited"}
	for _, path := range allowed {
		called = false
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, path, nil))
		if recorder.Code != http.StatusNoContent {
			t.Fatalf("%s status=%d, want %d", path, recorder.Code, http.StatusNoContent)
		}
		if !called {
			t.Fatalf("%s should reach the wrapped handler", path)
		}
	}
}
