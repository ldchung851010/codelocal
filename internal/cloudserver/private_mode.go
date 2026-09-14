package cloudserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"os"
	"strings"

	"github.com/0xmarkhydra/codelocal/internal/cloud"
	"github.com/0xmarkhydra/codelocal/internal/webauth"
)

type privateModeConfig struct {
	Enabled       bool
	OwnerEmail    string
	OwnerPassword string
}

func privateModeConfigFromEnv() (privateModeConfig, error) {
	rawMode := strings.ToLower(strings.TrimSpace(os.Getenv("CODELOCAL_PRIVATE_MODE")))
	enabled := false
	switch rawMode {
	case "", "0", "false", "off", "no":
		enabled = false
	case "1", "true", "on", "yes":
		enabled = true
	default:
		return privateModeConfig{}, fmt.Errorf("CODELOCAL_PRIVATE_MODE must be one of 1/true/on/yes or 0/false/off/no")
	}
	if !enabled {
		return privateModeConfig{}, nil
	}

	email := strings.ToLower(strings.TrimSpace(os.Getenv("CODELOCAL_OWNER_EMAIL")))
	password := os.Getenv("CODELOCAL_OWNER_PASSWORD")
	if email == "" {
		return privateModeConfig{}, errors.New("CODELOCAL_OWNER_EMAIL is required when private mode is enabled")
	}
	parsed, err := mail.ParseAddress(email)
	if err != nil || !strings.EqualFold(parsed.Address, email) {
		return privateModeConfig{}, errors.New("CODELOCAL_OWNER_EMAIL must be a valid email address")
	}
	if password == "" {
		return privateModeConfig{}, errors.New("CODELOCAL_OWNER_PASSWORD is required when private mode is enabled")
	}

	return privateModeConfig{Enabled: true, OwnerEmail: email, OwnerPassword: password}, nil
}

func ensurePrivateOwnerAdmin(email string) error {
	if strings.TrimSpace(os.Getenv("CODELOCAL_ADMIN_EMAILS")) == "" && strings.TrimSpace(os.Getenv("CODELOCAL_ADMIN_EMAIL")) == "" {
		if err := os.Setenv("CODELOCAL_ADMIN_EMAIL", email); err != nil {
			return fmt.Errorf("configure private owner admin: %w", err)
		}
	}
	if !cloud.IsAdminEmail(email) {
		return errors.New("private owner must be included in CODELOCAL_ADMIN_EMAILS or CODELOCAL_ADMIN_EMAIL")
	}
	return nil
}

// PreparePrivateModeEnvironment runs before New so any constructor-time admin
// checks see the intended private owner rather than the public deployment default.
func PreparePrivateModeEnvironment() error {
	cfg, err := privateModeConfigFromEnv()
	if err != nil {
		return err
	}
	if !cfg.Enabled {
		return nil
	}
	return ensurePrivateOwnerAdmin(cfg.OwnerEmail)
}

// ConfigurePrivateMode bootstraps the single private owner and closes the
// public signup/invite surface. Login, browser sessions, OAuth, and device
// pairing continue through their existing handlers unchanged.
func ConfigurePrivateMode(ctx context.Context, server *Server) error {
	cfg, err := privateModeConfigFromEnv()
	if err != nil {
		return err
	}
	if !cfg.Enabled {
		return nil
	}
	if server == nil || server.Store == nil || server.HTTP == nil || server.HTTP.Handler == nil {
		return errors.New("private mode requires an initialized cloud server")
	}
	// Keep this check here as a fail-closed defense for callers that invoke
	// ConfigurePrivateMode directly instead of using the normal main startup path.
	if err := ensurePrivateOwnerAdmin(cfg.OwnerEmail); err != nil {
		return err
	}

	hash, salt, err := webauth.HashPassword(cfg.OwnerPassword)
	if err != nil {
		return fmt.Errorf("CODELOCAL_OWNER_PASSWORD is invalid: %w", err)
	}
	if _, _, err := server.Store.EnsureBootstrapOwner(ctx, cfg.OwnerEmail, hash, salt); err != nil {
		return fmt.Errorf("bootstrap private owner: %w", err)
	}

	server.HTTP.Handler = privateModeSignupGuard(server.HTTP.Handler)
	return nil
}

func privateModeBlockedPath(path string) bool {
	for _, prefix := range []string{
		"/signup",
		"/invite",
		"/api/v1/auth/signup-verification",
		"/api/v1/invite",
	} {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}

func privateModeSignupGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if privateModeBlockedPath(r.URL.Path) {
			w.Header().Set("Cache-Control", "no-store")
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}
