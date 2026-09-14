package cloud

import (
	"context"
	"errors"
	"strings"
	"time"
)

// EnsureBootstrapOwner creates the private deployment owner exactly once.
// It intentionally bypasses referral admission because it is only used by the
// server's explicit private-mode bootstrap path. Existing accounts are never
// overwritten, so restarting the service cannot reset an owner's password.
func (s *Store) EnsureBootstrapOwner(ctx context.Context, email, passwordHash, passwordSalt string) (User, bool, error) {
	email = normalizeEmail(email)
	if email == "" || strings.TrimSpace(passwordHash) == "" || strings.TrimSpace(passwordSalt) == "" {
		return User{}, false, errors.New("BOOTSTRAP_OWNER_CREDENTIALS_REQUIRED")
	}

	existing, err := s.UserByEmail(ctx, email)
	if err != nil {
		return User{}, false, err
	}
	if existing != nil {
		return *existing, false, nil
	}

	for attempt := 0; attempt < 10; attempt++ {
		user := User{
			ID:             RandomHex(16),
			Email:          email,
			PasswordHash:   passwordHash,
			PasswordSalt:   passwordSalt,
			SecurityVersion: 1,
			ReferralCode:   RandomReferralCode(),
			CreatedAt:      time.Now().UnixMilli(),
		}
		_, err := s.DB.Exec(ctx, `INSERT INTO codelocal_users(id,email,password_hash,password_salt,referral_code,referred_by_code,created_at) VALUES($1,$2,$3,$4,$5,NULL,$6)`, user.ID, user.Email, user.PasswordHash, user.PasswordSalt, user.ReferralCode, user.CreatedAt)
		if err == nil {
			return user, true, nil
		}
		if strings.Contains(err.Error(), "23505") || strings.Contains(strings.ToLower(err.Error()), "duplicate") {
			existing, lookupErr := s.UserByEmail(ctx, email)
			if lookupErr != nil {
				return User{}, false, lookupErr
			}
			if existing != nil {
				return *existing, false, nil
			}
			continue
		}
		return User{}, false, err
	}
	return User{}, false, errors.New("REFERRAL_CODE_GENERATION_FAILED")
}
