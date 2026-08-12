package main

import (
	"path"
	"strings"
	"testing"
)

// Real `uci show wireguard_server` output from a GL-BE14000, trimmed of key material.
const sampleWGShow = `wireguard_server.main_server=servers
wireguard_server.main_server.address_v4='10.1.0.1/24'
wireguard_server.main_server.port='51820'
wireguard_server.main_server.public_key='SERVERPUB='
wireguard_server.main_server.client_to_client='1'
wireguard_server.peer_1046=peers
wireguard_server.peer_1046.name='Haven'
wireguard_server.peer_1046.peer_id='1046'
wireguard_server.peer_1046.client_ip='10.1.0.2/24'
wireguard_server.peer_1046.enabled='1'
`

func TestParseUCIShow(t *testing.T) {
	tr := parseUCIShow(sampleWGShow)

	if got := tr.typ["main_server"]; got != "servers" {
		t.Errorf("section type = %q, want servers", got)
	}
	// Quotes must be stripped, or every value is used with literal ' around it.
	if got := tr.get("main_server", "address_v4"); got != "10.1.0.1/24" {
		t.Errorf("address_v4 = %q, want unquoted 10.1.0.1/24", got)
	}
	if got := tr.sectionsOfType("peers"); len(got) != 1 || got[0] != "peer_1046" {
		t.Errorf("peers = %v, want [peer_1046]", got)
	}
	// File order matters: "the only server" must be picked deterministically.
	if len(tr.order) == 0 || tr.order[0] != "main_server" {
		t.Errorf("order = %v, want main_server first", tr.order)
	}
	// A missing option must read as empty, not panic on a nil inner map.
	if got := tr.get("nonexistent", "nope"); got != "" {
		t.Errorf("missing option = %q, want empty", got)
	}
}

func TestParseUCIShowSkipsJunkRatherThanFailing(t *testing.T) {
	tr := parseUCIShow("garbage line with no equals\n\nwireguard_server.s=servers\n")
	if tr.typ["s"] != "servers" {
		t.Error("a malformed line stopped the rest of the config from parsing")
	}
}

// Handing two devices the same address silently breaks whichever connects second, so
// allocation must skip the server and every peer already holding one.
func TestNextFreeClientIPSkipsServerAndPeers(t *testing.T) {
	addr, bits, err := nextFreeClientIP("10.1.0.1/24", []string{"10.1.0.2/24"})
	if err != nil {
		t.Fatal(err)
	}
	if addr.String() != "10.1.0.3" {
		t.Errorf("got %s, want 10.1.0.3 (.1 is the server, .2 is taken)", addr)
	}
	if bits != 24 {
		t.Errorf("prefix bits = %d, want 24", bits)
	}
}

func TestNextFreeClientIPFillsGaps(t *testing.T) {
	// .2 released, .3 still held: the gap should be reused rather than climbing forever.
	addr, _, err := nextFreeClientIP("10.1.0.1/24", []string{"10.1.0.3/24", "10.1.0.4/24"})
	if err != nil {
		t.Fatal(err)
	}
	if addr.String() != "10.1.0.2" {
		t.Errorf("got %s, want 10.1.0.2", addr)
	}
}

// The failure that matters: a full subnet must be an error, never a silently reused
// address. This is the assertion that would catch someone "fixing" exhaustion by wrapping.
func TestNextFreeClientIPExhaustionIsAnError(t *testing.T) {
	// /30 -> .1 server, .2 usable, .3 broadcast. One peer fills it.
	if _, _, err := nextFreeClientIP("10.9.9.1/30", []string{"10.9.9.2/30"}); err == nil {
		t.Fatal("a full subnet returned an address instead of an error")
	}
}

func TestNextFreeClientIPSkipsBroadcast(t *testing.T) {
	addr, _, err := nextFreeClientIP("10.9.9.1/29", []string{
		"10.9.9.2/29", "10.9.9.3/29", "10.9.9.4/29", "10.9.9.5/29", "10.9.9.6/29",
	})
	if err == nil {
		t.Fatalf("got %s; .7 is the broadcast address and must not be handed out", addr)
	}
}

func TestNextFreeClientIPRejectsBadCIDR(t *testing.T) {
	if _, _, err := nextFreeClientIP("10.1.0.1", nil); err == nil {
		t.Error("a bare address (no prefix) should be rejected")
	}
}

func TestNextPeerIDAvoidsCollision(t *testing.T) {
	tr := parseUCIShow(sampleWGShow)
	if got := nextPeerID(tr); got != 1047 {
		t.Errorf("next peer id = %d, want 1047 (1046 exists)", got)
	}
	if got := nextPeerID(parseUCIShow("wireguard_server.main_server=servers\n")); got != 1001 {
		t.Errorf("first peer id = %d, want 1001", got)
	}
}

func TestClientConfigRendersValidIni(t *testing.T) {
	c := wgClientConfig{
		PrivateKey: "PRIV=", Address: "10.1.0.3/24", DNS: "10.1.0.1", MTU: 1420,
		ServerPubKey: "PUB=", AllowedIPs: "0.0.0.0/0",
		Endpoint: "eq64078.glddns.com:51820", Keepalive: 25,
	}
	got := c.String()
	for _, want := range []string{
		"[Interface]", "PrivateKey = PRIV=", "Address = 10.1.0.3/24", "DNS = 10.1.0.1",
		"MTU = 1420", "[Peer]", "PublicKey = PUB=", "AllowedIPs = 0.0.0.0/0",
		"Endpoint = eq64078.glddns.com:51820", "PersistentKeepalive = 25",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("config missing %q:\n%s", want, got)
		}
	}
	// [Interface] must precede [Peer] or wg-quick assigns the keys to the wrong section.
	if strings.Index(got, "[Interface]") > strings.Index(got, "[Peer]") {
		t.Error("[Peer] came before [Interface]")
	}
}

func TestClientConfigOmitsUnsetOptionals(t *testing.T) {
	c := wgClientConfig{PrivateKey: "P", Address: "10.1.0.3/24", ServerPubKey: "S",
		AllowedIPs: "0.0.0.0/0", Endpoint: "h:51820"}
	got := c.String()
	for _, unwanted := range []string{"DNS =", "MTU =", "PersistentKeepalive ="} {
		if strings.Contains(got, unwanted) {
			t.Errorf("emitted %q with no value set:\n%s", unwanted, got)
		}
	}
}

// A QR that does not vary with its content is a fixed image, which would scan as somebody
// else's tunnel. Cheap to assert, and the failure is otherwise invisible until a scan.
func TestRenderQRIsContentDependent(t *testing.T) {
	a, err := renderQR("[Interface]\nPrivateKey = AAA=\n")
	if err != nil {
		t.Fatal(err)
	}
	b, err := renderQR("[Interface]\nPrivateKey = BBB=\n")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("two different configs produced identical QR output")
	}
	if !strings.ContainsAny(a, "█▀▄ ") {
		t.Errorf("QR output does not look like block characters:\n%.120s", a)
	}
	// Deterministic, so a redeploy of the same client does not produce a different image.
	again, _ := renderQR("[Interface]\nPrivateKey = AAA=\n")
	if a != again {
		t.Error("QR rendering is not deterministic")
	}
}

func TestRenderQRHandlesAFullConfig(t *testing.T) {
	c := wgClientConfig{
		PrivateKey: strings.Repeat("A", 44) + "=", Address: "10.1.0.3/24", DNS: "10.1.0.1",
		MTU: 1420, ServerPubKey: strings.Repeat("B", 44) + "=", AllowedIPs: "0.0.0.0/0",
		Endpoint: "eq64078.glddns.com:51820", Keepalive: 25,
	}
	qr, err := renderQR(c.String())
	if err != nil {
		t.Fatalf("a realistic config failed to encode: %v", err)
	}
	// Must fit a normal terminal, or it cannot be scanned off the screen.
	lines := strings.Split(strings.TrimRight(qr, "\n"), "\n")
	if len(lines) > 45 {
		t.Errorf("QR is %d rows tall; too big to scan from a standard terminal", len(lines))
	}
	if len(lines) < 10 {
		t.Errorf("QR is only %d rows; suspiciously small for a full config", len(lines))
	}
}

// The bug this pins: a request scope is matched as a LITERAL against policy globs, so
// emitting "*" here makes a policy naming one server fail to match it.
func TestWGScopesAreLiteralsNotGlobs(t *testing.T) {
	for _, in := range []wgNewClientIn{{Name: "a"}, {Name: "a", Server: "main_server"}} {
		for _, s := range wgScopes(in) {
			if strings.ContainsAny(s, "*?[") {
				t.Errorf("scope %q contains a glob metacharacter", s)
			}
		}
	}
	// A policy for the specific server must cover an explicit request for it.
	if ok, _ := path.Match("wireguard_server.main_server", wgScopes(wgNewClientIn{Server: "main_server"})[0]); !ok {
		t.Error("an explicit server request is not covered by a policy naming that server")
	}
	// And a config-level policy must cover the unspecified case.
	if ok, _ := path.Match("wireguard_server*", wgScopes(wgNewClientIn{})[0]); !ok {
		t.Error("the default request is not covered by a wireguard_server* policy")
	}
}

func TestFirstJSONIPv4(t *testing.T) {
	const status = `{"up":true,"ipv6-address":[{"address":"fd00::1","mask":64}],` +
		`"ipv4-address":[{"address":"51.155.210.106","mask":32}]}`
	if got := firstJSONIPv4(status); got != "51.155.210.106" {
		t.Errorf("got %q, want 51.155.210.106 (must skip the IPv6 address)", got)
	}
	if got := firstJSONIPv4(`{"up":false}`); got != "" {
		t.Errorf("got %q, want empty when there is no address", got)
	}
}

func TestFirstAddr(t *testing.T) {
	if got := firstAddr("10.1.0.1/24"); got != "10.1.0.1" {
		t.Errorf("got %q, want 10.1.0.1", got)
	}
	if got := firstAddr("nonsense"); got != "" {
		t.Errorf("got %q, want empty for an unparseable CIDR", got)
	}
}
