package cloud

import (
	"context"
	"testing"
)

func TestEnsureBootstrapOwnerRejectsMissingCredentialsBeforeDatabaseAccess(t *testing.T) {
	store := &Store{}
	if _, _, err := store.EnsureBootstrapOwner(context.Background(), "", "", ""); err == nil {
		t.Fatal("expected missing bootstrap credentials to fail closed")
	}
}
