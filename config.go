package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ponytail: we parse UCI ourselves rather than shelling to `uci show`. It is ~60 lines
// of trivial format, and doing it in-process makes the whole policy engine unit-testable
// on a workstation that has no uci binary. The `uci` binary is still used for *router*
// config via the tools -- just not for our own.

type uciSection struct {
	Type    string
	Name    string
	Options map[string]string
	Lists   map[string][]string
}

func parseUCI(r *bufio.Scanner) []uciSection {
	var out []uciSection
	var cur *uciSection
	for r.Scan() {
		fields, ok := splitUCI(r.Text())
		if !ok || len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "config":
			if cur != nil {
				out = append(out, *cur)
			}
			cur = &uciSection{Options: map[string]string{}, Lists: map[string][]string{}}
			if len(fields) > 1 {
				cur.Type = fields[1]
			}
			if len(fields) > 2 {
				cur.Name = fields[2]
			}
		case "option":
			if cur != nil && len(fields) > 2 {
				cur.Options[fields[1]] = fields[2]
			}
		case "list":
			if cur != nil && len(fields) > 2 {
				cur.Lists[fields[1]] = append(cur.Lists[fields[1]], fields[2])
			}
		}
	}
	if cur != nil {
		out = append(out, *cur)
	}
	return out
}

// splitUCI tokenises a UCI line, honouring single and double quotes and dropping # comments.
func splitUCI(line string) ([]string, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil, false
	}
	var fields []string
	var buf strings.Builder
	var quote rune
	for _, c := range line {
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			} else {
				buf.WriteRune(c)
			}
		case c == '\'' || c == '"':
			quote = c
		case c == ' ' || c == '\t':
			if buf.Len() > 0 {
				fields = append(fields, buf.String())
				buf.Reset()
			}
		case c == '#' && len(fields) >= 3:
			// trailing comment after a complete option line
			if buf.Len() > 0 {
				fields = append(fields, buf.String())
				buf.Reset()
			}
			return fields, true
		default:
			buf.WriteRune(c)
		}
	}
	if buf.Len() > 0 {
		fields = append(fields, buf.String())
	}
	return fields, true
}

// ---------------------------------------------------------------- policies

type Policy struct {
	Client    string
	Tools     []string
	Scopes    []string // globs matched against a per-tool scope string
	MaxPerMin int
	Expires   time.Time // zero == never expires
	Enabled   bool

	mu   sync.Mutex
	hits []time.Time // rolling 60s window; process-scoped by design (see README)
}

type Config struct {
	Listen     string
	AuditPath  string
	AuditMaxMB int
	Policies   []*Policy
}

const (
	defaultListen     = "127.0.0.1:8730"
	defaultAuditPath  = "/etc/openwrt-mcp/audit.jsonl"
	defaultAuditMaxMB = 16
)

func LoadConfig(configPath string) (*Config, error) {
	c := &Config{Listen: defaultListen, AuditPath: defaultAuditPath, AuditMaxMB: defaultAuditMaxMB}
	f, err := os.Open(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil // no config == no policies == deny everything gated. Valid state.
		}
		return nil, err
	}
	defer f.Close()

	for _, s := range parseUCI(bufio.NewScanner(f)) {
		switch s.Type {
		case "server":
			if v := s.Options["listen"]; v != "" {
				c.Listen = v
			}
			if v := s.Options["audit"]; v != "" {
				c.AuditPath = v
			}
			if v, err := strconv.Atoi(s.Options["audit_max_mb"]); err == nil && v > 0 {
				c.AuditMaxMB = v
			}
		case "policy":
			p, err := policyFromSection(s)
			if err != nil {
				return nil, fmt.Errorf("policy %q: %w", s.Name, err)
			}
			c.Policies = append(c.Policies, p)
		}
	}
	return c, nil
}

func policyFromSection(s uciSection) (*Policy, error) {
	p := &Policy{
		Client:    s.Options["client"],
		Tools:     s.Lists["tools"],
		Scopes:    s.Lists["scopes"],
		MaxPerMin: 60,
		Enabled:   s.Options["enabled"] != "0",
	}
	if p.Client == "" {
		return nil, fmt.Errorf("missing 'client'")
	}
	// `option tools 'a b c'` is accepted alongside `list tools 'a'` for terser hand-editing.
	if v := s.Options["tools"]; v != "" {
		p.Tools = append(p.Tools, strings.Fields(v)...)
	}
	if v := s.Options["scopes"]; v != "" {
		p.Scopes = append(p.Scopes, strings.Fields(v)...)
	}
	if len(p.Tools) == 0 {
		return nil, fmt.Errorf("grants no tools")
	}
	if v, err := strconv.Atoi(s.Options["max_per_min"]); err == nil && v > 0 {
		p.MaxPerMin = v
	}
	if v := s.Options["expires"]; v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			if t, err = time.Parse("2006-01-02", v); err != nil {
				return nil, fmt.Errorf("bad 'expires' %q: want RFC3339 or YYYY-MM-DD", v)
			}
		}
		p.Expires = t
	}
	return p, nil
}

// Authorise reports whether any single policy permits client/tool and covers *every*
// scope in scopes. Denial is the default: a miss on any dimension falls through to the
// next policy and, if none match, to a refusal. A policy can only ever *add* permission,
// never widen another policy's -- which is why all scopes must be satisfied by one policy
// rather than collected across several.
//
// One rate token is consumed per authorised call, not per scope.
func (c *Config) Authorise(client, tool string, scopes []string, now time.Time) (bool, string) {
	var sawClientTool bool
	var uncovered string
	for _, p := range c.Policies {
		if !p.Enabled || p.Client != client || !contains(p.Tools, tool) {
			continue
		}
		if !p.Expires.IsZero() && now.After(p.Expires) {
			continue
		}
		sawClientTool = true
		if miss, ok := firstUncovered(p.Scopes, scopes); !ok {
			uncovered = miss
			continue
		}
		if !p.takeToken(now) {
			return false, fmt.Sprintf("rate limit: policy for %q allows %d calls/min to %s", client, p.MaxPerMin, tool)
		}
		return true, ""
	}
	if sawClientTool && uncovered != "" {
		return false, fmt.Sprintf("denied: %s is granted to %q but no policy scope covers %q\n"+
			"  grant it: openwrt-mcp allow %s %s '%s' 60m", tool, client, uncovered, client, tool, uncovered)
	}
	return false, fmt.Sprintf("denied: no policy grants %s to %q\n"+
		"  grant it: openwrt-mcp allow %s %s '%s' 60m", tool, client, client, tool, orStar(strings.Join(scopes, " ")))
}

// firstUncovered returns the first scope not matched by any glob. ok is true only when
// every scope is covered (vacuously true for an empty scope list).
func firstUncovered(globs, scopes []string) (string, bool) {
	for _, s := range scopes {
		if !matchAny(globs, s) {
			return s, false
		}
	}
	return "", true
}

func (p *Policy) takeToken(now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	cut := now.Add(-time.Minute)
	kept := p.hits[:0]
	for _, h := range p.hits {
		if h.After(cut) {
			kept = append(kept, h)
		}
	}
	p.hits = kept
	if len(p.hits) >= p.MaxPerMin {
		return false
	}
	p.hits = append(p.hits, now)
	return true
}

func matchAny(globs []string, s string) bool {
	for _, g := range globs {
		if g == "*" {
			return true
		}
		if ok, err := path.Match(g, s); err == nil && ok {
			return true
		}
	}
	return false
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

func orStar(s string) string {
	if s == "" {
		return "*"
	}
	return s
}

// ---------------------------------------------------------------- tokens

// Tokens are stored hash-only: the raw bearer is shown once at pair time and never
// recoverable. File format is "<sha256hex> <client name>" per line, mode 0600.
type TokenStore struct {
	path   string
	mu     sync.RWMutex
	byHash map[string]string
	mtime  time.Time
}

func LoadTokens(p string) (*TokenStore, error) {
	ts := &TokenStore{path: p, byHash: map[string]string{}}
	return ts, ts.reload()
}

func (ts *TokenStore) reload() error {
	st, err := os.Stat(ts.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	f, err := os.Open(ts.path)
	if err != nil {
		return err
	}
	defer f.Close()
	fresh := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.SplitN(strings.TrimSpace(sc.Text()), " ", 2)
		if len(parts) == 2 && parts[0] != "" {
			fresh[parts[0]] = parts[1]
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	ts.mu.Lock()
	ts.byHash, ts.mtime = fresh, st.ModTime()
	ts.mu.Unlock()
	return nil
}

// reloadIfChanged picks up `pair` and `unpair` run from the CLI while the daemon is
// live. Without it a revoked token would stay valid until the next restart -- the
// dangerous direction of a stale cache, and a bug Haven shipped once already.
func (ts *TokenStore) reloadIfChanged() {
	st, err := os.Stat(ts.path)
	if err != nil {
		return
	}
	ts.mu.RLock()
	same := st.ModTime().Equal(ts.mtime)
	ts.mu.RUnlock()
	if !same {
		_ = ts.reload()
	}
}

// Resolve maps a raw bearer token to a client name in constant time with respect to
// the stored digests, so it cannot be used as a timing oracle.
func (ts *TokenStore) Resolve(raw string) (string, bool) {
	if raw == "" {
		return "", false
	}
	ts.reloadIfChanged()
	sum := sha256.Sum256([]byte(raw))
	want := []byte(hex.EncodeToString(sum[:]))
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	var name string
	var found int
	for h, n := range ts.byHash {
		if subtle.ConstantTimeCompare([]byte(h), want) == 1 {
			name, found = n, 1
		}
	}
	return name, found == 1
}

func (ts *TokenStore) Mint(client string) (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	raw := base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(raw))
	ts.mu.Lock()
	ts.byHash[hex.EncodeToString(sum[:])] = client
	ts.mu.Unlock()
	return raw, ts.save()
}

func (ts *TokenStore) Revoke(client string) int {
	ts.mu.Lock()
	n := 0
	for h, c := range ts.byHash {
		if c == client {
			delete(ts.byHash, h)
			n++
		}
	}
	ts.mu.Unlock()
	if n > 0 {
		_ = ts.save()
	}
	return n
}

func (ts *TokenStore) Clients() []string {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	seen := map[string]bool{}
	var out []string
	for _, c := range ts.byHash {
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

func (ts *TokenStore) save() error {
	if err := os.MkdirAll(path.Dir(ts.path), 0o700); err != nil {
		return err
	}
	var b strings.Builder
	ts.mu.RLock()
	for h, c := range ts.byHash {
		fmt.Fprintf(&b, "%s %s\n", h, c)
	}
	ts.mu.RUnlock()
	tmp := ts.path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, ts.path)
}
