package main

import (
	"bufio"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func parse(t *testing.T, s string) *Config {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "openwrt-mcp")
	writeFile(t, p, s)
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	return cfg
}

func TestParseUCI(t *testing.T) {
	secs := parseUCI(bufio.NewScanner(strings.NewReader(`
# a comment
config server
	option listen '127.0.0.1:9999'
	option audit_max_mb 4

config policy 'named'
	option client "claude code"
	list tools 'ubus_call'
	list tools 'logread'
	list scopes 'network.*'
`)))
	if len(secs) != 2 {
		t.Fatalf("want 2 sections, got %d: %+v", len(secs), secs)
	}
	if got := secs[0].Options["listen"]; got != "127.0.0.1:9999" {
		t.Errorf("listen = %q", got)
	}
	if got := secs[1].Name; got != "named" {
		t.Errorf("section name = %q", got)
	}
	if got := secs[1].Options["client"]; got != "claude code" {
		t.Errorf("double-quoted value with space = %q", got)
	}
	if got := secs[1].Lists["tools"]; len(got) != 2 || got[1] != "logread" {
		t.Errorf("tools list = %v", got)
	}
}

func TestConfigDefaultsAndMissingFile(t *testing.T) {
	cfg, err := LoadConfig(filepath.Join(t.TempDir(), "nope"))
	if err != nil {
		t.Fatalf("missing config should not be an error: %v", err)
	}
	if cfg.Listen != defaultListen || len(cfg.Policies) != 0 {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
	// The whole point: no config == nothing is authorised.
	if ok, reason := cfg.Authorise("anyone", "ubus_call", []string{"network.status"}, time.Now()); ok {
		t.Fatalf("empty config authorised a call; reason=%q", reason)
	}
}

const basePolicy = `
config policy
	option client 'claude-code'
	list tools 'ubus_call'
	list tools 'logread'
	list scopes 'network.*'
	list scopes 'iwinfo.*'
	option max_per_min '3'
`

func TestAuthorise(t *testing.T) {
	cfg := parse(t, basePolicy)
	now := time.Now()

	cases := []struct {
		name         string
		client, tool string
		scopes       []string
		want         bool
		reasonHas    string
	}{
		{"granted tool and scope", "claude-code", "ubus_call", []string{"network.status"}, true, ""},
		{"second scope glob", "claude-code", "ubus_call", []string{"iwinfo.scan"}, true, ""},
		{"scopeless tool", "claude-code", "logread", nil, true, ""},
		{"wrong client", "someone-else", "ubus_call", []string{"network.status"}, false, "no policy grants"},
		{"ungranted tool", "claude-code", "exec", []string{"reboot"}, false, "no policy grants"},
		{"uncovered scope", "claude-code", "ubus_call", []string{"system.reboot"}, false, "no policy scope covers"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ok, reason := cfg.Authorise(c.client, c.tool, c.scopes, now)
			if ok != c.want {
				t.Fatalf("Authorise = %v (want %v), reason=%q", ok, c.want, reason)
			}
			if !ok && !strings.Contains(reason, c.reasonHas) {
				t.Fatalf("reason %q does not mention %q", reason, c.reasonHas)
			}
			if !ok && !strings.Contains(reason, "openwrt-mcp allow") {
				t.Errorf("refusal should tell the human how to grant it: %q", reason)
			}
		})
	}
}

// A multi-scope call must be covered *entirely* by one policy. This is the uci_apply case:
// touching network.lan.ipaddr and firewall.@zone[0].input needs both covered, and a policy
// that covers only one must not authorise the pair.
func TestAuthoriseRequiresEveryScope(t *testing.T) {
	cfg := parse(t, basePolicy)
	ok, reason := cfg.Authorise("claude-code", "ubus_call",
		[]string{"network.status", "system.reboot"}, time.Now())
	if ok {
		t.Fatal("authorised a call whose second scope was uncovered")
	}
	if !strings.Contains(reason, "system.reboot") {
		t.Errorf("refusal should name the uncovered scope, got %q", reason)
	}
}

func TestAuthoriseExpiry(t *testing.T) {
	cfg := parse(t, basePolicy+"\toption expires '2020-01-01'\n")
	if ok, _ := cfg.Authorise("claude-code", "logread", nil, time.Now()); ok {
		t.Fatal("expired policy still authorised")
	}
	// ...and the same policy would have worked before it expired, proving the gate is
	// the expiry and not some unrelated mismatch.
	if ok, r := cfg.Authorise("claude-code", "logread", nil, time.Date(2019, 6, 1, 0, 0, 0, 0, time.UTC)); !ok {
		t.Fatalf("policy should have been valid before expiry: %s", r)
	}
}

func TestAuthoriseDisabled(t *testing.T) {
	cfg := parse(t, basePolicy+"\toption enabled '0'\n")
	if ok, _ := cfg.Authorise("claude-code", "logread", nil, time.Now()); ok {
		t.Fatal("disabled policy still authorised")
	}
}

func TestRateLimit(t *testing.T) {
	cfg := parse(t, basePolicy) // max_per_min 3
	now := time.Now()
	for i := 0; i < 3; i++ {
		if ok, r := cfg.Authorise("claude-code", "logread", nil, now); !ok {
			t.Fatalf("call %d should be allowed: %s", i+1, r)
		}
	}
	ok, reason := cfg.Authorise("claude-code", "logread", nil, now)
	if ok {
		t.Fatal("4th call within the window should be rate limited")
	}
	if !strings.Contains(reason, "rate limit") {
		t.Errorf("want a rate-limit reason, got %q", reason)
	}
	// The window is rolling, so the same call succeeds once the minute has passed.
	if ok, r := cfg.Authorise("claude-code", "logread", nil, now.Add(61*time.Second)); !ok {
		t.Fatalf("call after the window should be allowed: %s", r)
	}
}

func TestPolicyRejectsMalformed(t *testing.T) {
	for _, bad := range []string{
		"config policy\n\tlist tools 'logread'\n",                                         // no client
		"config policy\n\toption client 'x'\n",                                            // no tools
		"config policy\n\toption client 'x'\n\tlist tools 't'\n\toption expires 'soon'\n", // bad date
	} {
		dir := t.TempDir()
		p := filepath.Join(dir, "cfg")
		writeFile(t, p, bad)
		if _, err := LoadConfig(p); err == nil {
			t.Errorf("expected an error for malformed policy:\n%s", bad)
		}
	}
}

func TestTokenStore(t *testing.T) {
	p := filepath.Join(t.TempDir(), "tokens")
	ts, err := LoadTokens(p)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := ts.Mint("claude-code")
	if err != nil {
		t.Fatal(err)
	}
	if name, ok := ts.Resolve(raw); !ok || name != "claude-code" {
		t.Fatalf("Resolve(minted) = %q,%v", name, ok)
	}
	for _, bad := range []string{"", "wrong", raw + "x", raw[:len(raw)-1]} {
		if _, ok := ts.Resolve(bad); ok {
			t.Errorf("Resolve(%q) unexpectedly succeeded", bad)
		}
	}

	// The raw token must not be recoverable from disk -- only its digest is stored.
	if strings.Contains(readFile(t, p), raw) {
		t.Fatal("raw token was written to the token file")
	}

	// Reload from disk and confirm it still resolves.
	ts2, err := LoadTokens(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ts2.Resolve(raw); !ok {
		t.Fatal("token did not survive a reload")
	}
	if n := ts2.Revoke("claude-code"); n != 1 {
		t.Fatalf("Revoke removed %d tokens, want 1", n)
	}
	if _, ok := ts2.Resolve(raw); ok {
		t.Fatal("revoked token still resolves")
	}
}

func TestParseDuration(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"60m": time.Hour,
		"2h":  2 * time.Hour,
		"30d": 30 * 24 * time.Hour,
	} {
		got, err := parseDuration(in)
		if err != nil || got != want {
			t.Errorf("parseDuration(%q) = %v,%v want %v", in, got, err, want)
		}
	}
	if _, err := parseDuration("banana"); err == nil {
		t.Error("expected an error for a nonsense duration")
	}
}

func TestAppendPolicyRoundTrips(t *testing.T) {
	p := filepath.Join(t.TempDir(), "cfg")
	if err := appendPolicy(p, "claude-code", "ubus_call,logread", "network.* iwinfo.*", "30d"); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatalf("policy written by `allow` did not parse back: %v", err)
	}
	if len(cfg.Policies) != 1 {
		t.Fatalf("want 1 policy, got %d", len(cfg.Policies))
	}
	if ok, r := cfg.Authorise("claude-code", "ubus_call", []string{"network.status"}, time.Now()); !ok {
		t.Fatalf("granted call denied: %s", r)
	}
	if ok, _ := cfg.Authorise("claude-code", "ubus_call", []string{"system.reboot"}, time.Now()); ok {
		t.Fatal("scope outside the grant was authorised")
	}
}
