package cloud

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestEnsureBootstrapOwnerRejectsMissingCredentialsBeforeDatabaseAccess(t *testing.T) {
	store := &Store{}
	if _, _, err := store.EnsureBootstrapOwner(context.Background(), "", "", ""); err == nil {
		t.Fatal("expected missing bootstrap credentials to fail closed")
	}
}

func TestEnsureBootstrapOwnerRejectsUnavailableStore(t *testing.T) {
	store := &Store{}
	if _, _, err := store.EnsureBootstrapOwner(context.Background(), "owner@example.com", "hash", "salt"); err == nil {
		t.Fatal("expected unavailable bootstrap store to fail closed")
	}
}

func TestIsUniqueViolationUsesPostgresErrorCode(t *testing.T) {
	if !isUniqueViolation(&pgconn.PgError{Code: "23505"}) {
		t.Fatal("expected PostgreSQL unique violation to be recognized")
	}
	if isUniqueViolation(&pgconn.PgError{Code: "23503"}) {
		t.Fatal("foreign-key violation must not be treated as unique collision")
	}
	if isUniqueViolation(errors.New("duplicate 23505 text only")) {
		t.Fatal("plain error text must not be treated as a PostgreSQL unique collision")
	}
}
