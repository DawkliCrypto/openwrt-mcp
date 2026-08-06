package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"testing"
)

// glClientsReply reproduces the reply shape `ubus call gl-clients list` actually returns on
// a GL-BE14000 (firmware 4.9.0). Every structural detail here was taken from a real capture:
// per-client last_rx/last_tx arrays of exactly 60 elements, counters encoded as JSON
// *strings* rather than numbers, and an empty ipv6 array. MAC, IP and name are substituted.
//
// With 49 clients attached the real reply measured 100,587 bytes.
func glClientsReply(clients int) string {
	series := make([]string, 60)
	for i := range series {
		series[i] = "25198"
	}
	cl := map[string]any{}
	for i := 0; i < clients; i++ {
		mac := fmt.Sprintf("AA:BB:CC:00:%02X:%02X", i/256, i%256)
		cl[mac] = map[string]any{
			"ip": "192.168.1.10", "mac": mac, "name": "test-client",
			"iface": "br-lan", "online": true, "online_time": 1234,
			"ipv6":    []string{},
			"last_rx": series, "last_tx": series,
			"rx": "100", "tx": "200", "total_rx": "300", "total_tx": "400",
		}
	}
	b, _ := json.Marshal(map[string]any{"clients": cl})
	return string(b)
}

func TestPruneUbusJSONShortensGlClients(t *testing.T) {
	in := glClientsReply(49)
	out := pruneUbusJSON(in)

	if out == in {
		t.Fatal("gl-clients reply came back unpruned; the 60-element series should have been cut")
	}
	if len(out) >= len(in) {
		t.Errorf("pruning did not shrink the reply: %d -> %d bytes", len(in), len(out))
	}

	// The whole point of pruning the decoded tree instead of truncating the string.
	body := out[:strings.LastIndex(out, "\n\n[pruned:")]
	var v map[string]any
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		t.Fatalf("pruned output is not valid JSON: %v", err)
	}

	clients, ok := v["clients"].(map[string]any)
	if !ok {
		t.Fatal("clients key lost during pruning")
	}
	if len(clients) != 49 {
		t.Errorf("pruning dropped whole clients: got %d, want 49", len(clients))
	}
	for mac, c := range clients {
		rx := c.(map[string]any)["last_rx"].([]any)
		// 16 kept + 1 marker.
		if len(rx) != maxArrayElems+1 {
			t.Fatalf("%s last_rx = %d elements, want %d", mac, len(rx), maxArrayElems+1)
		}
		if last, _ := rx[len(rx)-1].(string); last != "...+44 more" {
			t.Errorf("%s missing truncation marker, got %q", mac, last)
		}
		// A field that was never long must survive untouched.
		if c.(map[string]any)["ip"] != "192.168.1.10" {
			t.Errorf("%s ip mangled by pruning", mac)
		}
	}
	if !strings.Contains(out, "[pruned:") {
		t.Error("pruned output does not say it was pruned")
	}
}

func TestPruneUbusJSONLeavesShortRepliesByteIdentical(t *testing.T) {
	// `ubus call system board` -- nothing to prune. It must come back exactly as ubus
	// printed it, tabs and all, not silently reserialised.
	in := "{\n\t\"kernel\": \"5.4.281\",\n\t\"hostname\": \"GL-BE14000\"\n}\n"
	if out := pruneUbusJSON(in); out != in {
		t.Errorf("short reply was rewritten:\n got %q\nwant %q", out, in)
	}
}

func TestPruneUbusJSONPassesThroughNonJSON(t *testing.T) {
	// ubus prints plain text on failure; it must not be mistaken for a payload to prune.
	in := "Command failed: Not found"
	if out := pruneUbusJSON(in); out != in {
		t.Errorf("non-JSON output was altered: got %q", out)
	}
}

func TestPruneUbusJSONBoundary(t *testing.T) {
	// Exactly at the cap: nothing to drop, so nothing may change.
	at := `{"a":[` + strings.TrimSuffix(strings.Repeat(`1,`, maxArrayElems), ",") + `]}`
	if out := pruneUbusJSON(at); out != at {
		t.Errorf("array of exactly %d elements was pruned: %q", maxArrayElems, out)
	}
	// One over: exactly one element dropped.
	over := `{"a":[` + strings.TrimSuffix(strings.Repeat(`1,`, maxArrayElems+1), ",") + `]}`
	out := pruneUbusJSON(over)
	if !strings.Contains(out, "...+1 more") {
		t.Errorf("array of %d elements was not pruned: %q", maxArrayElems+1, out)
	}
}

// fakeUbus puts a stub `ubus` on PATH that prints body and exits 0.
func fakeUbus(t *testing.T, body string) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\ncat <<'ENDOFBODY'\n" + body + "\nENDOFBODY\n"
	if err := os.WriteFile(filepath.Join(dir, "ubus"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// The pruner working in isolation says nothing about whether ubus_call uses it. This asserts
// the wiring: delete the pruneUbusJSON call from ubusCall and this test must go red.
func TestUbusCallPrunesItsReply(t *testing.T) {
	fakeUbus(t, glClientsReply(49))

	out, summary, err := ubusCall(context.Background(), ubusCallIn{Object: "gl-clients", Method: "list"})
	if err != nil {
		t.Fatalf("ubusCall: %v", err)
	}
	if summary != "gl-clients.list" {
		t.Errorf("summary = %q, want gl-clients.list", summary)
	}
	if !strings.Contains(out, "[pruned:") {
		t.Fatal("ubus_call returned an unpruned reply -- the pruner is not wired into the tool")
	}
	if len(out) >= len(glClientsReply(49)) {
		t.Errorf("reply not shortened: %d bytes", len(out))
	}
}

func TestUbusCallRequiresObjectAndMethod(t *testing.T) {
	if _, _, err := ubusCall(context.Background(), ubusCallIn{Object: "system"}); err == nil {
		t.Error("missing method was accepted")
	}
}

func TestTextResultTruncatesOversizedOutput(t *testing.T) {
	res := textResult(strings.Repeat("x", maxResultBytes+5000))
	got := res.Content[0].(*mcp.TextContent).Text
	if len(got) <= maxResultBytes {
		t.Fatalf("truncated body is %d bytes, expected the cap plus a notice", len(got))
	}
	if !strings.Contains(got, "TRUNCATED") {
		t.Error("oversized output was cut without saying so")
	}
	if strings.Count(got, "x") != maxResultBytes {
		t.Errorf("kept %d bytes of payload, want %d", strings.Count(got, "x"), maxResultBytes)
	}
}

func TestTextResultLeavesNormalOutputAlone(t *testing.T) {
	res := textResult("uptime: 2:26")
	if got := res.Content[0].(*mcp.TextContent).Text; got != "uptime: 2:26" {
		t.Errorf("normal output altered: %q", got)
	}
}
