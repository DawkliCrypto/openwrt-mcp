package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// RFC 6238 Appendix B test vectors, SHA-1, 8 digits truncated to our 6.
//
// A hand-rolled TOTP that is subtly wrong still looks like it works -- codes are generated
// and compared by the same broken code, so enrolment and unlock agree with each other while
// no real authenticator app can produce an accepted code. Only external vectors catch that.
func TestTOTPMatchesRFC6238Vectors(t *testing.T) {
	// The RFC's ASCII seed "12345678901234567890" in base32.
	const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	for _, tc := range []struct {
		unix int64
		want string // last 6 digits of the RFC's 8-digit value
	}{
		{59, "287082"},         // 94287082
		{1111111109, "081804"}, // 07081804
		{1111111111, "050471"}, // 14050471
		{1234567890, "005924"}, // 89005924
		{2000000000, "279037"}, // 69279037
	} {
		got, err := totpAt(secret, uint64(tc.unix)/30)
		if err != nil {
			t.Fatalf("t=%d: %v", tc.unix, err)
		}
		if got != tc.want {
			t.Errorf("t=%d: got %s, want %s", tc.unix, got, tc.want)
		}
	}
}

func newMFA(t *testing.T) (*MFAStore, string) {
	t.Helper()
	dir := t.TempDir()
	m, err := LoadMFA(filepath.Join(dir, "mfa"))
	if err != nil {
		t.Fatal(err)
	}
	return m, dir
}

func codeNow(t *testing.T, m *MFAStore, client string, now time.Time) string {
	t.Helper()
	m.mu.Lock()
	secret := m.secrets[client]
	m.mu.Unlock()
	c, err := totpAt(secret, uint64(now.Unix())/30)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestUnlockAcceptsAValidCodeAndOpensAWindow(t *testing.T) {
	m, _ := newMFA(t)
	if _, _, err := m.Enrol("a", "openwrt-mcp", "testrouter"); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1700000000, 0)

	if _, open := m.UnlockedUntil("a", now); open {
		t.Fatal("locked by default -- enrolment alone must not unlock anything")
	}
	until, err := m.Unlock("a", codeNow(t, m, "a", now), 15*time.Minute, now)
	if err != nil {
		t.Fatalf("valid code rejected: %v", err)
	}
	if _, open := m.UnlockedUntil("a", now.Add(14*time.Minute)); !open {
		t.Error("window closed early")
	}
	if _, open := m.UnlockedUntil("a", until.Add(time.Second)); open {
		t.Error("window did not expire")
	}
}

func TestUnlockRejectsWrongCode(t *testing.T) {
	m, _ := newMFA(t)
	m.Enrol("a", "openwrt-mcp", "testrouter")
	now := time.Unix(1700000000, 0)

	for _, bad := range []string{"000000", "12345", "1234567", "", "abcdef"} {
		if _, err := m.Unlock("a", bad, time.Minute, now); err == nil {
			t.Errorf("accepted bad code %q", bad)
		}
	}
	if _, open := m.UnlockedUntil("a", now); open {
		t.Fatal("a failed unlock opened the window")
	}
}

// A code is single-use. Without this it stays valid for its whole ~90s acceptance span, so
// one shoulder-surf or one code left in a scrollback is reusable.
func TestUnlockRefusesAReplayedCode(t *testing.T) {
	m, _ := newMFA(t)
	m.Enrol("a", "openwrt-mcp", "testrouter")
	now := time.Unix(1700000000, 0)
	code := codeNow(t, m, "a", now)

	if _, err := m.Unlock("a", code, time.Minute, now); err != nil {
		t.Fatal(err)
	}
	m.Lock("a")
	if _, err := m.Unlock("a", code, time.Minute, now); err == nil {
		t.Fatal("the same code was accepted twice")
	}
}

// An unenrolled client must fail exactly like a wrong code: a different message tells an
// attacker which clients are worth attacking.
func TestUnlockUnenrolledIsIndistinguishableFromWrongCode(t *testing.T) {
	m, _ := newMFA(t)
	m.Enrol("enrolled", "openwrt-mcp", "testrouter")
	now := time.Unix(1700000000, 0)

	_, errUnenrolled := m.Unlock("stranger", "123456", time.Minute, now)
	_, errWrong := m.Unlock("enrolled", "000000", time.Minute, now)
	if errUnenrolled == nil || errWrong == nil {
		t.Fatal("both should fail")
	}
	if errUnenrolled.Error() != errWrong.Error() {
		t.Errorf("messages differ and leak enrolment state: %q vs %q", errUnenrolled, errWrong)
	}
}

func TestEnrolPersistsAndRotates(t *testing.T) {
	m, dir := newMFA(t)
	s1, uri, err := m.Enrol("a", "openwrt-mcp", "testrouter")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(uri, "otpauth://totp/") || !strings.Contains(uri, "secret="+s1) {
		t.Errorf("otpauth URI is not scannable: %q", uri)
	}

	// Mode matters: this is the one credential stored in recoverable form.
	st, err := os.Stat(filepath.Join(dir, "mfa"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("secret file mode is %v, want 0600", st.Mode().Perm())
	}

	reloaded, err := LoadMFA(filepath.Join(dir, "mfa"))
	if err != nil {
		t.Fatal(err)
	}
	if !reloaded.Enrolled("a") {
		t.Fatal("enrolment did not survive a reload")
	}

	// Re-enrolling is the lost-phone path: the old secret must stop working.
	now := time.Unix(1700000000, 0)
	oldCode, _ := totpAt(s1, uint64(now.Unix())/30)
	s2, _, _ := m.Enrol("a", "openwrt-mcp", "testrouter")
	if s1 == s2 {
		t.Fatal("re-enrolment reused the secret")
	}
	if _, err := m.Unlock("a", oldCode, time.Minute, now); err == nil {
		t.Error("a code from the replaced secret still unlocks")
	}
}

func TestEnrolClearsAnExistingUnlock(t *testing.T) {
	m, _ := newMFA(t)
	m.Enrol("a", "openwrt-mcp", "testrouter")
	now := time.Unix(1700000000, 0)
	if _, err := m.Unlock("a", codeNow(t, m, "a", now), time.Hour, now); err != nil {
		t.Fatal(err)
	}
	m.Enrol("a", "openwrt-mcp", "testrouter") // e.g. rotating after a suspected compromise
	if _, open := m.UnlockedUntil("a", now); open {
		t.Error("re-enrolment left the old unlock open")
	}
}

// The policy side: which tools demand a factor, and refusing configs that cannot work.
func TestPolicyMFAParsing(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config")
	os.WriteFile(p, []byte(`
config policy
	option client 'a'
	list tools 'ubus_call'
	list tools 'exec'
	list scopes '*'
	list mfa_tools 'exec'
	option mfa_window '5m'
`), 0o600)

	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	pol := cfg.Policies[0]
	if !pol.NeedsMFA("exec") {
		t.Error("exec should need a factor")
	}
	if pol.NeedsMFA("ubus_call") {
		t.Error("ubus_call was not listed and must not need one")
	}
	if pol.MFAWindow != 5*time.Minute {
		t.Errorf("window = %v, want 5m", pol.MFAWindow)
	}
}

func TestPolicyMFADefaultsToOff(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config")
	os.WriteFile(p, []byte("config policy\n\toption client 'a'\n\tlist tools 'exec'\n\tlist scopes '*'\n"), 0o600)
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Policies[0].NeedsMFA("exec") {
		t.Fatal("MFA must be opt-in; an existing config gained a requirement it never asked for")
	}
}

// A policy naming a tool it does not grant is a typo that would otherwise sit there doing
// nothing, looking like protection.
func TestPolicyRejectsMFAToolItDoesNotGrant(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config")
	os.WriteFile(p, []byte("config policy\n\toption client 'a'\n\tlist tools 'ubus_call'\n"+
		"\tlist scopes '*'\n\tlist mfa_tools 'exec'\n"), 0o600)
	if _, err := LoadConfig(p); err == nil {
		t.Fatal("expected an error for mfa_tools naming an ungranted tool")
	}
}

func TestPolicyMFAStarCoversEveryTool(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config")
	os.WriteFile(p, []byte("config policy\n\toption client 'a'\n\tlist tools 'exec'\n"+
		"\tlist tools 'ubus_call'\n\tlist scopes '*'\n\tlist mfa_tools '*'\n"), 0o600)
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{"exec", "ubus_call"} {
		if !cfg.Policies[0].NeedsMFA(tool) {
			t.Errorf("'*' should cover %s", tool)
		}
	}
}

// The gate the tool wrapper actually consults. Everything above tests the parts; this tests
// that they are joined up, which is the failure mode that leaves a control looking present.
func TestMFAGate(t *testing.T) {
	m, dir := newMFA(t)
	m.Enrol("a", "openwrt-mcp", "testrouter")
	s := &Server{statePath: dir, mfa: m}
	now := time.Unix(1700000000, 0)

	gated := &Policy{Client: "a", Tools: []string{"exec", "ubus_call"},
		MFATools: []string{"exec"}, MFAWindow: 15 * time.Minute, Enabled: true}
	plain := &Policy{Client: "a", Tools: []string{"exec"}, Enabled: true}

	if r := s.mfaGate(plain, "a", "exec", now); r != "" {
		t.Errorf("a policy with no mfa_tools must not gate: %q", r)
	}
	if r := s.mfaGate(gated, "a", "ubus_call", now); r != "" {
		t.Errorf("a tool not listed in mfa_tools must not gate: %q", r)
	}

	r := s.mfaGate(gated, "a", "exec", now)
	if r == "" {
		t.Fatal("locked client was allowed through the gate")
	}
	if !strings.Contains(r, "mfa_unlock") {
		t.Errorf("refusal does not say how to proceed: %q", r)
	}

	if _, err := m.Unlock("a", codeNow(t, m, "a", now), 15*time.Minute, now); err != nil {
		t.Fatal(err)
	}
	if r := s.mfaGate(gated, "a", "exec", now); r != "" {
		t.Errorf("unlocked client was still refused: %q", r)
	}
	// And it re-locks when the window lapses rather than staying open.
	if r := s.mfaGate(gated, "a", "exec", now.Add(16*time.Minute)); r == "" {
		t.Error("the window never closed")
	}
}

// One client's unlock must not open another's.
func TestMFAUnlockIsPerClient(t *testing.T) {
	m, dir := newMFA(t)
	m.Enrol("a", "openwrt-mcp", "testrouter")
	m.Enrol("b", "openwrt-mcp", "testrouter")
	s := &Server{statePath: dir, mfa: m}
	now := time.Unix(1700000000, 0)
	gated := &Policy{Tools: []string{"exec"}, MFATools: []string{"exec"},
		MFAWindow: time.Minute, Enabled: true}

	m.Unlock("a", codeNow(t, m, "a", now), time.Minute, now)
	if r := s.mfaGate(gated, "a", "exec", now); r != "" {
		t.Errorf("a should be unlocked: %q", r)
	}
	if r := s.mfaGate(gated, "b", "exec", now); r == "" {
		t.Error("b was unlocked by a's code")
	}
}

// Regression: `openwrt-mcp mfa enrol` is a separate process writing the secret file. A
// running daemon that only read it at startup rejects every code from a freshly enrolled
// client as "invalid code" -- which is what happened on a real router, with no hint that a
// restart was what it wanted.
func TestUnlockSeesAnEnrolmentByAnotherProcess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mfa")

	daemon, err := LoadMFA(path) // started before anything was enrolled
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1700000000, 0)
	if _, err := daemon.Unlock("a", "123456", time.Minute, now); err == nil {
		t.Fatal("unlocked with no enrolment at all")
	}

	// A different process enrols, exactly as the CLI does.
	cli, err := LoadMFA(path)
	if err != nil {
		t.Fatal(err)
	}
	secret, _, err := cli.Enrol("a", "openwrt-mcp", "testrouter")
	if err != nil {
		t.Fatal(err)
	}
	// mtime granularity: make sure the change is observable.
	os.Chtimes(path, now.Add(time.Hour), now.Add(time.Hour))

	code, _ := totpAt(secret, uint64(now.Unix())/30)
	if _, err := daemon.Unlock("a", code, time.Minute, now); err != nil {
		t.Fatalf("the running daemon did not pick up the new enrolment: %v", err)
	}
	if !daemon.Enrolled("a") {
		t.Error("Enrolled() still reports the stale view")
	}
}

// Rotating a secret is what you do when it might be compromised, so a window opened under
// the old one must not survive the reload.
func TestReloadClosesAWindowWhenTheSecretRotates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mfa")
	daemon, _ := LoadMFA(path)
	cli, _ := LoadMFA(path)

	s1, _, _ := cli.Enrol("a", "openwrt-mcp", "testrouter")
	now := time.Unix(1700000000, 0)
	os.Chtimes(path, now, now)
	c1, _ := totpAt(s1, uint64(now.Unix())/30)
	if _, err := daemon.Unlock("a", c1, time.Hour, now); err != nil {
		t.Fatal(err)
	}
	if _, open := daemon.UnlockedUntil("a", now); !open {
		t.Fatal("should be unlocked")
	}

	cli.Enrol("a", "openwrt-mcp", "testrouter") // rotate
	os.Chtimes(path, now.Add(time.Hour), now.Add(time.Hour))
	daemon.Unlock("a", "000000", time.Minute, now) // any call triggers the reload
	if _, open := daemon.UnlockedUntil("a", now); open {
		t.Error("the window survived a secret rotation")
	}
}

// Two routers must not produce indistinguishable entries in an authenticator app.
func TestEnrolLabelsTheDevice(t *testing.T) {
	m, _ := newMFA(t)
	_, uri, err := m.Enrol("claude-code", "openwrt-mcp", "GL-BE14000")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(uri, "claude-code@GL-BE14000") {
		t.Errorf("account label does not name the router: %q", uri)
	}

	// A second router with the same client must differ, or you cannot tell them apart.
	m2, _ := newMFA(t)
	_, uri2, _ := m2.Enrol("claude-code", "openwrt-mcp", "GL-BE10000")
	if uri == uri2 {
		t.Fatal("two routers produced identical labels")
	}
	if !strings.Contains(uri2, "claude-code@GL-BE10000") {
		t.Errorf("second label wrong: %q", uri2)
	}

	// No label available: fall back to the bare client rather than a stray '@'.
	m3, _ := newMFA(t)
	_, uri3, _ := m3.Enrol("claude-code", "openwrt-mcp", "")
	if strings.Contains(uri3, "@") && strings.Contains(uri3, "claude-code@?") {
		t.Errorf("malformed fallback label: %q", uri3)
	}
	if !strings.Contains(uri3, "claude-code") {
		t.Errorf("client name missing: %q", uri3)
	}
}
