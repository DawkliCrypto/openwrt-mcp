package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Optional second factor for the tools that can change or read anything.
//
// The bearer token is something the workstation has. If that workstation is compromised the
// token goes with it, and with a broad grant that is root on the router. A TOTP code is
// something *you* have, on a different device, so a stolen token alone stops being enough.
//
// Deliberately not a code per call. An agent makes bursts of calls, and prompting for six
// digits each time would push people to disable it -- a control that is too annoying to leave
// on protects nothing. Instead one code unlocks a time-boxed window, the way sudo does. The
// window is per client, held in memory only: a daemon restart drops every unlock, which errs
// toward asking again.
//
// Standard RFC 6238: SHA-1, 6 digits, 30-second step. That is what Google Authenticator,
// Aegis, 1Password and the rest implement, so enrolment is a QR scan and nothing bespoke.

const (
	totpStep    = 30 * time.Second
	totpDigits  = 6
	totpSkew    = 1 // accept the adjacent steps: routers drift, phones drift
	mfaFileMode = 0o600
)

// defaultMFAWindow is how long one code keeps the gated tools open.
const defaultMFAWindow = 15 * time.Minute

// MFAStore holds one TOTP secret per client, plus the live unlock state.
//
// The secret is stored raw because TOTP is symmetric -- unlike the bearer tokens, which are
// only ever kept as digests. That is a real difference in blast radius, so the file is 0600
// and lives beside the token store, and `mfa enrol` is the only thing that ever prints it.
type MFAStore struct {
	path string

	mu      sync.Mutex
	secrets map[string]string    // client -> base32 secret
	unlocks map[string]time.Time // client -> unlocked until
	lastCtr map[string]uint64    // client -> last accepted time-step, for replay
}

func LoadMFA(path string) (*MFAStore, error) {
	m := &MFAStore{
		path:    path,
		secrets: map[string]string{},
		unlocks: map[string]time.Time{},
		lastCtr: map[string]uint64{},
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return m, nil // no enrolments == no MFA == every policy unaffected. Valid state.
		}
		return nil, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		client, secret, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		m.secrets[client] = strings.TrimSpace(secret)
	}
	return m, nil
}

// Enrol mints a new secret for a client, replacing any existing one. Returns the secret and
// an otpauth:// URI for a QR code. Re-enrolling invalidates the old secret, which is the
// recovery path when a phone is lost.
func (m *MFAStore) Enrol(client, issuer string) (secret, uri string, err error) {
	buf := make([]byte, 20) // 160 bits, per RFC 4226 section 4
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	secret = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf)

	m.mu.Lock()
	m.secrets[client] = secret
	delete(m.unlocks, client) // a new secret must not inherit an old unlock
	delete(m.lastCtr, client)
	snapshot := make(map[string]string, len(m.secrets))
	for k, v := range m.secrets {
		snapshot[k] = v
	}
	m.mu.Unlock()

	if err := m.save(snapshot); err != nil {
		return "", "", err
	}

	label := url.PathEscape(issuer + ":" + client)
	uri = fmt.Sprintf("otpauth://totp/%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d",
		label, secret, url.QueryEscape(issuer), totpDigits, int(totpStep.Seconds()))
	return secret, uri, nil
}

func (m *MFAStore) save(secrets map[string]string) error {
	var b strings.Builder
	b.WriteString("# openwrt-mcp TOTP secrets. Treat as credentials: anyone who reads this\n" +
		"# file can generate valid codes. Re-run `openwrt-mcp mfa enrol <client>` to rotate.\n")
	clients := make([]string, 0, len(secrets))
	for c := range secrets {
		clients = append(clients, c)
	}
	sortStrings(clients)
	for _, c := range clients {
		fmt.Fprintf(&b, "%s %s\n", c, secrets[c])
	}
	if err := os.MkdirAll(filepath.Dir(m.path), 0o700); err != nil {
		return err
	}
	// Write-and-rename so a crash mid-write cannot leave a half-file that locks you out.
	tmp := m.path + ".new"
	if err := os.WriteFile(tmp, []byte(b.String()), mfaFileMode); err != nil {
		return err
	}
	return os.Rename(tmp, m.path)
}

func (m *MFAStore) Enrolled(client string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.secrets[client] != ""
}

func (m *MFAStore) Clients() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.secrets))
	for c := range m.secrets {
		out = append(out, c)
	}
	sortStrings(out)
	return out
}

// Unlock validates a code and opens the window. The error text is deliberately the same for
// "no secret" and "wrong code" -- distinguishing them tells an attacker which clients are
// worth attacking.
func (m *MFAStore) Unlock(client, code string, window time.Duration, now time.Time) (time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	secret := m.secrets[client]
	code = strings.TrimSpace(code)
	if secret == "" || len(code) != totpDigits {
		return time.Time{}, fmt.Errorf("invalid code")
	}

	step := uint64(now.Unix()) / uint64(totpStep.Seconds())
	for skew := -totpSkew; skew <= totpSkew; skew++ {
		ctr := step + uint64(skew)
		want, err := totpAt(secret, ctr)
		if err != nil {
			return time.Time{}, fmt.Errorf("invalid code")
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) != 1 {
			continue
		}
		// Replay: a code is single-use. Without this, a code shoulder-surfed or captured
		// from a log is good for its whole 90-second acceptance span.
		if last, seen := m.lastCtr[client]; seen && ctr <= last {
			return time.Time{}, fmt.Errorf("code already used")
		}
		m.lastCtr[client] = ctr
		until := now.Add(window)
		m.unlocks[client] = until
		return until, nil
	}
	return time.Time{}, fmt.Errorf("invalid code")
}

// UnlockedUntil returns when the client's window closes, and whether it is open now.
func (m *MFAStore) UnlockedUntil(client string, now time.Time) (time.Time, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	until, ok := m.unlocks[client]
	if !ok || !now.Before(until) {
		return time.Time{}, false
	}
	return until, true
}

// Lock closes the window immediately -- the "I am done, re-lock it" path.
func (m *MFAStore) Lock(client string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.unlocks, client)
}

func totpAt(secret string, counter uint64) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).
		DecodeString(strings.ToUpper(strings.ReplaceAll(secret, " ", "")))
	if err != nil {
		return "", err
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	// Dynamic truncation, RFC 4226 section 5.4.
	off := sum[len(sum)-1] & 0x0f
	v := (uint32(sum[off]&0x7f) << 24) | (uint32(sum[off+1]) << 16) |
		(uint32(sum[off+2]) << 8) | uint32(sum[off+3])

	mod := uint32(1)
	for i := 0; i < totpDigits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", totpDigits, v%mod), nil
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// parseMFAWindow accepts the same duration spellings as grant expiry.
func parseMFAWindow(s string) (time.Duration, error) {
	if strings.TrimSpace(s) == "" {
		return defaultMFAWindow, nil
	}
	d, err := parseDuration(s)
	if err != nil {
		return 0, err
	}
	if d <= 0 {
		return 0, fmt.Errorf("mfa_window must be positive")
	}
	return d, nil
}
