package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"time"
)

// `openwrt-mcp status --json` backs the router's own web UI.
//
// Deliberately a CLI subcommand rather than an HTTP endpoint. The daemon's only listener is
// loopback and unauthenticated reachability is explicitly not treated as identity, so adding
// a second HTTP surface would mean either leaving policy and audit data readable to every
// process on the router, or storing a bearer token on the router for the UI to present --
// the same hole the README rejects for rpcd's credentialed uci apply.
//
// A CLI read has neither problem: oui-httpd already runs as root, and root can read the
// state directory regardless, so this exposes nothing that caller could not already reach.
// It also keeps every administrative operation on one surface.

type statusReport struct {
	Version  string         `json:"version"`
	Source   string         `json:"source"`
	Listen   string         `json:"listen"`
	Running  bool           `json:"running"`
	Clients  []clientReport `json:"clients"`
	Policies []policyReport `json:"policies"`
	Audit    []auditRow     `json:"audit"`
	Counts   map[string]int `json:"counts"`
}

type clientReport struct {
	Name string `json:"name"`
	// No token and no digest. Tokens are unrecoverable by construction and digests are
	// credential material; neither belongs in a browser.
	Policies int `json:"policies"`
}

type policyReport struct {
	Client    string   `json:"client"`
	Tools     []string `json:"tools"`
	Scopes    []string `json:"scopes"`
	MaxPerMin int      `json:"max_per_min"`
	Expires   string   `json:"expires,omitempty"`
	Expired   bool     `json:"expired"`
	Enabled   bool     `json:"enabled"`
}

type auditRow struct {
	Time    string `json:"time"`
	Client  string `json:"client"`
	Tool    string `json:"tool,omitempty"`
	Scope   string `json:"scope,omitempty"`
	Outcome string `json:"outcome"`
	Summary string `json:"summary,omitempty"`
	Error   string `json:"error,omitempty"`
}

func runStatus(configPath, statePath string, auditLines int, asJSON bool) error {
	cfg, err := LoadConfig(configPath)
	if err != nil {
		return err
	}

	rep := statusReport{
		Version: version,
		Source:  sourceURL,
		Listen:  cfg.Listen,
		Running: daemonRunning(cfg.Listen),
		Counts:  map[string]int{},
	}

	perClient := map[string]int{}
	now := time.Now()
	for _, p := range cfg.Policies {
		pr := policyReport{
			Client: p.Client, Tools: p.Tools, Scopes: p.Scopes,
			MaxPerMin: p.MaxPerMin, Enabled: p.Enabled,
		}
		if !p.Expires.IsZero() {
			pr.Expires = p.Expires.Format(time.RFC3339)
			pr.Expired = now.After(p.Expires)
		}
		rep.Policies = append(rep.Policies, pr)
		perClient[p.Client]++
	}

	// Pairings come from the token store, not from the policy list: a client can be paired
	// with nothing granted, and that is worth seeing rather than hiding.
	if ts, err := LoadTokens(statePath + "/tokens"); err == nil {
		names := ts.Clients()
		sort.Strings(names)
		for _, n := range names {
			rep.Clients = append(rep.Clients, clientReport{Name: n, Policies: perClient[n]})
		}
	}

	rep.Audit = tailAudit(cfg.AuditPath, auditLines)
	rep.Counts["clients"] = len(rep.Clients)
	rep.Counts["policies"] = len(rep.Policies)
	rep.Counts["audit_shown"] = len(rep.Audit)

	if !asJSON {
		return writeStatusText(os.Stdout, rep)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

// daemonRunning checks that *this daemon* is serving on the configured address, not merely
// that the port is occupied. A bare TCP dial is a proxy for the wrong question: 8730 is a
// perfectly ordinary port for something else to hold -- an ssh -L on a workstation will
// answer it happily -- and reporting that as "running" would be a lie in exactly the case a
// status pane exists to catch. So ask /health and require it to identify itself.
func daemonRunning(listen string) bool {
	if listen == "" {
		listen = defaultListen
	}
	c, err := net.DialTimeout("tcp", listen, 2*time.Second)
	if err != nil {
		return false
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := fmt.Fprintf(c, "GET /health HTTP/1.0\r\nHost: %s\r\n\r\n", listen); err != nil {
		return false
	}
	body, _ := io.ReadAll(io.LimitReader(c, 4096))
	return strings.Contains(string(body), "openwrt-mcp")
}

// tailAudit returns the last n entries of the JSONL audit log, oldest first.
//
// The auditor has already redacted secret-looking values on the way in, so nothing further is
// stripped here -- doing it twice invites the two implementations to disagree about what
// counts as a secret. Args are dropped entirely: they are the bulkiest field and the least
// useful in a status pane.
func tailAudit(path string, n int) []auditRow {
	if n <= 0 {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	// A ring buffer keeps this O(n) in memory no matter how large the log has grown.
	ring := make([]string, n)
	count := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		ring[count%n] = line
		count++
	}

	start, total := 0, count
	if total > n {
		start, total = count%n, n
	}
	out := make([]auditRow, 0, total)
	for i := 0; i < total; i++ {
		var e AuditEvent
		if json.Unmarshal([]byte(ring[(start+i)%n]), &e) != nil {
			continue
		}
		out = append(out, auditRow{
			Time: e.Time, Client: e.Client, Tool: e.Tool, Scope: e.Scope,
			Outcome: string(e.Outcome), Summary: e.Summary, Error: firstLine(e.Error),
		})
	}
	return out
}

// firstLine keeps a refusal's headline and drops the "grant it: ..." remedy that follows,
// which is actionable at a terminal and just noise in a table.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func writeStatusText(w io.Writer, r statusReport) error {
	state := "stopped"
	if r.Running {
		state = "running"
	}
	fmt.Fprintf(w, "openwrt-mcp %s -- %s on %s\n", r.Version, state, r.Listen)
	fmt.Fprintf(w, "%d paired client(s), %d policy/policies\n", len(r.Clients), len(r.Policies))
	for _, c := range r.Clients {
		fmt.Fprintf(w, "  %s (%d policy/policies)\n", c.Name, c.Policies)
	}
	for _, p := range r.Policies {
		exp := "never"
		if p.Expires != "" {
			exp = p.Expires
			if p.Expired {
				exp += " (EXPIRED)"
			}
		}
		fmt.Fprintf(w, "  %s: %s on %s, %d/min, expires %s\n",
			p.Client, strings.Join(p.Tools, ","), strings.Join(p.Scopes, " "), p.MaxPerMin, exp)
	}
	for _, a := range r.Audit {
		fmt.Fprintf(w, "  %s %-7s %-12s %s\n", a.Time, a.Outcome, a.Tool, a.Scope)
	}
	return nil
}
