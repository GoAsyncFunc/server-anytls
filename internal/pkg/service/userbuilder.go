// userbuilder.go translates uniproxy UserInfo records into sing-anytls
// User entries and exposes the email-style identifier used as the per-stream
// auth token. The format mirrors the sibling server-vless project so log
// lines and traffic keys read consistently across the GoAsyncFunc fleet.
package service

import (
	"fmt"
	"strconv"
	"strings"

	api "github.com/GoAsyncFunc/uniproxy/pkg"
	anytls "github.com/anytls/sing-anytls"
)

// BuildUserEmail returns the canonical "<inbound-tag>|<uid>|<uuid>"
// identifier used to associate a sing-anytls connection with a v2board
// user. uid == 0 produces an empty string so callers can detect an
// invalid input without a panic.
func BuildUserEmail(tag string, uid int, uuid string) string {
	if uid == 0 {
		return ""
	}
	return fmt.Sprintf("%s|%d|%s", tag, uid, uuid)
}

// BuildUsers maps the panel's user list to []anytls.User. Each user's
// password is set to their UUID; sing-anytls hashes it with sha256 to
// produce the lookup key on incoming connections. Entries with zero uid
// or empty uuid are skipped so the service map never accepts ambiguous
// auth.
func BuildUsers(tag string, users []api.UserInfo) []anytls.User {
	out := make([]anytls.User, 0, len(users))
	for _, u := range users {
		if u.Id == 0 || u.Uuid == "" {
			continue
		}
		out = append(out, anytls.User{
			Name:     BuildUserEmail(tag, u.Id, u.Uuid),
			Password: u.Uuid,
		})
	}
	return out
}

// ParseUIDFromEmail extracts the uid component from a value produced by
// BuildUserEmail. Empty input or malformed payloads return 0 with an
// error so callers can refuse the connection without panicking.
func ParseUIDFromEmail(email string) (int, error) {
	if email == "" {
		return 0, fmt.Errorf("empty email")
	}
	parts := strings.SplitN(email, "|", 3)
	if len(parts) < 3 {
		return 0, fmt.Errorf("invalid email format: %q", email)
	}
	uid, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, fmt.Errorf("invalid uid in email %q: %w", email, err)
	}
	if uid <= 0 {
		return 0, fmt.Errorf("non-positive uid in email %q", email)
	}
	return uid, nil
}
