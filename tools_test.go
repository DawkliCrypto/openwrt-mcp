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

// Regression: the first version of the pruner capped every array regardless of reply size.
// A smoke test caught it on `ubus call iwinfo devices` -- 17 radio interface names in 196
// bytes. It dropped a real interface AND the output grew to 202 bytes. This is the verbatim
// reply from a GL-BE14000.
func TestPruneUbusJSONLeavesShortListsIntact(t *testing.T) {
	in := "{\n\t\"devices\": [\n\t\t\"ra1\",\n\t\t\"rai15\",\n\t\t\"rai2\",\n\t\t\"rax2\",\n\t\t\"rai0\"," +
		"\n\t\t\"rax0\",\n\t\t\"rax15\",\n\t\t\"apcli0\",\n\t\t\"ra2\",\n\t\t\"rai3\",\n\t\t\"ra0\"," +
		"\n\t\t\"rai1\",\n\t\t\"rax1\",\n\t\t\"ra15\",\n\t\t\"apclii0\",\n\t\t\"apclix0\",\n\t\t\"ra3\"\n\t]\n}\n"

	out := pruneUbusJSON(in)
	if out != in {
		t.Errorf("a 17-element list in %d bytes was pruned; short replies must survive whole:\n%s",
			len(in), out)
	}
	if strings.Contains(out, "...+") {
		t.Error("a real interface name was replaced by a truncation marker")
	}
}

// Pruning must never make the output longer than what it replaced.
//
// A big reply whose only long array is barely over the cap and holds tiny values: dropping
// one 1-byte element to insert a 12-byte marker costs more than it saves, and the trailing
// notice costs more again. The size gate does not catch this -- the reply is over the
// threshold -- so only the never-grow check keeps it honest.
func TestPruneUbusJSONNeverGrowsTheReply(t *testing.T) {
	items := make([]any, maxArrayElems+1)
	for i := range items {
		items[i] = i
	}
	b, _ := json.MarshalIndent(map[string]any{
		"pad": strings.Repeat("p", pruneMinBytes),
		"a":   items,
	}, "", "\t")
	in := string(b)
	if len(in) < pruneMinBytes {
		t.Fatalf("fixture is %d bytes, needs to exceed the %d-byte gate", len(in), pruneMinBytes)
	}

	out := pruneUbusJSON(in)
	if len(out) > len(in) {
		t.Errorf("pruning grew the reply: %d -> %d bytes", len(in), len(out))
	}
	if out != in {
		t.Error("a prune that saves nothing should return the reply untouched")
	}
}

// The cap boundary is tested on the pruner itself, not through pruneUbusJSON. The wrapper
// declines any prune that does not shrink the reply, and trading one "1" for a
// "...+1 more" marker does not -- so exercising the cap through it would measure the
// economics, not the boundary.
func TestPrunerCapBoundary(t *testing.T) {
	arr := func(n int) []any {
		out := make([]any, n)
		for i := range out {
			out[i] = float64(i)
		}
		return out
	}

	// Exactly at the cap: untouched, nothing counted as dropped.
	p := &pruner{maxElems: maxArrayElems}
	got := p.walk(arr(maxArrayElems)).([]any)
	if len(got) != maxArrayElems || p.dropped != 0 {
		t.Errorf("at the cap: %d elements, dropped=%d; want %d, 0", len(got), p.dropped, maxArrayElems)
	}

	// One over: 16 kept plus a marker, one counted as dropped.
	p = &pruner{maxElems: maxArrayElems}
	got = p.walk(arr(maxArrayElems + 1)).([]any)
	if len(got) != maxArrayElems+1 || p.dropped != 1 {
		t.Fatalf("one over: %d elements, dropped=%d; want %d, 1", len(got), p.dropped, maxArrayElems+1)
	}
	if got[len(got)-1] != "...+1 more" {
		t.Errorf("marker = %v, want \"...+1 more\"", got[len(got)-1])
	}
	// The kept elements must be the first N, in order.
	if got[0] != float64(0) || got[maxArrayElems-1] != float64(maxArrayElems-1) {
		t.Error("pruning did not keep the first N elements in order")
	}

	// Nested arrays are pruned too, and every drop is counted.
	p = &pruner{maxElems: maxArrayElems}
	p.walk(map[string]any{"x": arr(20), "y": map[string]any{"z": arr(30)}})
	if p.dropped != 4+14 {
		t.Errorf("nested drops = %d, want %d", p.dropped, 4+14)
	}
}

// The size gate is about the reply, not the array: a long array inside a small reply stays.
func TestPruneUbusJSONSizeGateDominates(t *testing.T) {
	small, _ := json.Marshal(map[string]any{"a": make([]int, 500)})
	if len(small) >= pruneMinBytes {
		t.Fatalf("fixture is %d bytes, must be under the %d-byte gate", len(small), pruneMinBytes)
	}
	if out := pruneUbusJSON(string(small)); out != string(small) {
		t.Error("a 500-element array in a sub-threshold reply was pruned")
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
