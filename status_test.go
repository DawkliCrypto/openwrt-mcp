package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func statusFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// A status pane that shows a stale or wrong pairing list is worse than none, so pin what
// actually reaches the report -- and what must not.
func TestStatusReportShape(t *testing.T) {
	dir := t.TempDir()
	cfg := statusFile(t, dir, "config", `
config server
	option listen '127.0.0.1:9'
	option audit '`+dir+`/audit.jsonl'

config policy
	option client 'claude-code'
	list tools 'ubus_call'
	list scopes 'network.*'
	option enabled '1'
`)
	statusFile(t, dir, "audit.jsonl",
		`{"time":"2026-01-01T00:00:00Z","client":"a","tool":"ubus_call","scope":"system.board","outcome":"OK","duration_ms":2}`+"\n"+
			`{"time":"2026-01-01T00:00:01Z","client":"a","tool":"exec","scope":"cat","outcome":"DENIED","error":"denied: no policy\n  grant it: openwrt-mcp allow a exec 'cat' 60m","duration_ms":0}`+"\n")

	out := captureStdout(t, func() {
		if err := runStatus(cfg, dir, 20, true); err != nil {
			t.Fatal(err)
		}
	})

	var rep statusReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("status --json is not valid JSON: %v\n%s", err, out)
	}
	if rep.Version != version {
		t.Errorf("version = %q, want %q", rep.Version, version)
	}
	if len(rep.Policies) != 1 || rep.Policies[0].Client != "claude-code" {
		t.Fatalf("policies = %+v", rep.Policies)
	}
	if len(rep.Audit) != 2 {
		t.Fatalf("audit rows = %d, want 2", len(rep.Audit))
	}
	// Oldest first: a status pane that reverses time is actively misleading.
	if rep.Audit[0].Outcome != "OK" || rep.Audit[1].Outcome != "DENIED" {
		t.Errorf("audit out of order: %+v", rep.Audit)
	}
	// The remedy line belongs at a terminal, not in a table cell.
	if strings.Contains(rep.Audit[1].Error, "grant it:") {
		t.Errorf("multi-line refusal was not trimmed: %q", rep.Audit[1].Error)
	}
}

// Credential material must not reach a browser. This is the test that would catch someone
// helpfully adding a digest field to clientReport later.
func TestStatusNeverExposesTokenMaterial(t *testing.T) {
	dir := t.TempDir()
	cfg := statusFile(t, dir, "config", "config server\n\toption listen '127.0.0.1:9'\n")

	ts, err := LoadTokens(filepath.Join(dir, "tokens"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := ts.Mint("browser-test")
	if err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() {
		if err := runStatus(cfg, dir, 20, true); err != nil {
			t.Fatal(err)
		}
	})

	if !strings.Contains(out, "browser-test") {
		t.Error("paired client is missing from the report")
	}
	if strings.Contains(out, raw) {
		t.Fatal("the raw bearer token appears in status output")
	}
	// The stored digest must not leak either.
	stored, _ := os.ReadFile(filepath.Join(dir, "tokens"))
	for _, f := range strings.Fields(string(stored)) {
		if len(f) >= 32 && strings.Contains(out, f) {
			t.Fatalf("token store material appears in status output: %q", f)
		}
	}
}

func TestTailAuditKeepsOnlyTheLastN(t *testing.T) {
	dir := t.TempDir()
	var b strings.Builder
	for i := 0; i < 100; i++ {
		fmt.Fprintf(&b, `{"time":"t%d","client":"c","outcome":"OK","duration_ms":0}`+"\n", i)
	}
	p := statusFile(t, dir, "audit.jsonl", b.String())

	got := tailAudit(p, 5)
	if len(got) != 5 {
		t.Fatalf("got %d rows, want 5", len(got))
	}
	// Last five, oldest first.
	if got[0].Time != "t95" || got[4].Time != "t99" {
		t.Errorf("wrong window: first=%q last=%q", got[0].Time, got[4].Time)
	}
	if tailAudit(p, 0) != nil {
		t.Error("0 should return nothing")
	}
	if tailAudit(filepath.Join(dir, "absent"), 5) != nil {
		t.Error("a missing audit log should be empty, not an error")
	}
}

func TestTailAuditSkipsCorruptLines(t *testing.T) {
	dir := t.TempDir()
	p := statusFile(t, dir, "audit.jsonl",
		`{"time":"good1","client":"c","outcome":"OK","duration_ms":0}`+"\n"+
			"{ this is not json\n"+
			"\n"+
			`{"time":"good2","client":"c","outcome":"OK","duration_ms":0}`+"\n")
	got := tailAudit(p, 10)
	if len(got) != 2 || got[0].Time != "good1" || got[1].Time != "good2" {
		t.Errorf("a truncated line should be skipped, not fatal: %+v", got)
	}
}

// running must mean "this daemon", not "something holds the port".
func TestDaemonRunningDistinguishesOurDaemon(t *testing.T) {
	ours := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "openwrt-mcp %s ok\n", version)
	}))
	defer ours.Close()
	if !daemonRunning(strings.TrimPrefix(ours.URL, "http://")) {
		t.Error("our own /health was not recognised")
	}

	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Not Found", http.StatusNotFound)
	}))
	defer other.Close()
	if daemonRunning(strings.TrimPrefix(other.URL, "http://")) {
		t.Error("a different service on the port was reported as our daemon running")
	}

	// Nothing listening at all.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := l.Addr().String()
	l.Close()
	if daemonRunning(dead) {
		t.Error("a closed port was reported as running")
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w
	done := make(chan string)
	go func() {
		var sb strings.Builder
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			sb.Write(buf[:n])
			if err != nil {
				break
			}
		}
		done <- sb.String()
	}()
	fn()
	w.Close()
	os.Stdout = orig
	return <-done
}
