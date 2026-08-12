package main

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	qrcode "github.com/skip2/go-qrcode"
)

// Issuing a WireGuard client is three awkward steps by hand -- generate a keypair, find a
// free address in the server's subnet, and write a peer section the vendor UI still
// recognises -- followed by transcribing a config onto a phone. The transcription is what
// actually goes wrong, so this returns a scannable QR alongside the text.
//
// The peer is hot-added with `wg set` rather than by restarting the interface: a restart
// drops every established session, which is a poor trade for adding one client.

type wgNewClientIn struct {
	Name       string `json:"name" jsonschema:"label for the new client, e.g. 'laptop' or 'work-phone'"`
	Server     string `json:"server,omitempty" jsonschema:"server section name; defaults to the only one if there is exactly one"`
	Endpoint   string `json:"endpoint,omitempty" jsonschema:"host:port clients dial; defaults to the router's dynamic-DNS name, else its WAN address"`
	DNS        string `json:"dns,omitempty" jsonschema:"DNS server for the client; defaults to the server's own tunnel address"`
	AllowedIPs string `json:"allowed_ips,omitempty" jsonschema:"routes sent down the tunnel; defaults to 0.0.0.0/0 (full tunnel)"`
	MTU        int    `json:"mtu,omitempty" jsonschema:"client MTU; defaults to 1420"`
	Keepalive  int    `json:"persistent_keepalive,omitempty" jsonschema:"seconds; defaults to 25, which keeps NAT bindings alive"`
}

// wgScopes is the policy scope for an issue request. A request scope is matched as a
// literal against the policy's globs, so it must never itself contain a wildcard -- doing
// so makes a policy naming one server fail to match, and matches a wildcard policy only by
// accident. With no server named, the caller means "whichever server this router has",
// which the config-level scope expresses without pretending to know its name.
func wgScopes(in wgNewClientIn) []string {
	if in.Server == "" {
		return []string{"wireguard_server"}
	}
	return []string{"wireguard_server." + in.Server}
}

// ------------------------------------------------------------------ uci parsing

// uciTree is the parsed form of `uci show <config>`: section -> type, and
// section -> option -> value.
type uciTree struct {
	typ   map[string]string
	opt   map[string]map[string]string
	order []string // section names in file order, so "the first server" is deterministic
}

// parseUCIShow reads `uci show` output. Lines are either "cfg.section=type" or
// "cfg.section.option='value'". Unparseable lines are skipped rather than fatal --
// a vendor config with an odd line should not make the tool unusable.
func parseUCIShow(out string) *uciTree {
	t := &uciTree{typ: map[string]string{}, opt: map[string]map[string]string{}}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		eq := strings.Index(line, "=")
		if line == "" || eq < 0 {
			continue
		}
		lhs, rhs := line[:eq], strings.Trim(line[eq+1:], "'")
		parts := strings.Split(lhs, ".")
		switch len(parts) {
		case 2: // cfg.section=type
			sec := parts[1]
			if _, seen := t.typ[sec]; !seen {
				t.order = append(t.order, sec)
			}
			t.typ[sec] = rhs
		case 3: // cfg.section.option=value
			sec, opt := parts[1], parts[2]
			if t.opt[sec] == nil {
				t.opt[sec] = map[string]string{}
			}
			t.opt[sec][opt] = rhs
		}
	}
	return t
}

func (t *uciTree) get(sec, opt string) string { return t.opt[sec][opt] }

// sectionsOfType returns section names of the given uci type, in file order.
func (t *uciTree) sectionsOfType(typ string) []string {
	var out []string
	for _, s := range t.order {
		if t.typ[s] == typ {
			out = append(out, s)
		}
	}
	return out
}

// ------------------------------------------------------------------ address allocation

// nextFreeClientIP picks the lowest host address in the server's subnet that no peer
// already holds, skipping the server itself. Reusing an address silently breaks whichever
// client connects second, so a full subnet is an error rather than a wrap-around.
func nextFreeClientIP(serverCIDR string, used []string) (netip.Addr, int, error) {
	pfx, err := netip.ParsePrefix(serverCIDR)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("server address %q is not a CIDR: %w", serverCIDR, err)
	}
	taken := map[netip.Addr]bool{pfx.Addr(): true}
	for _, u := range used {
		if a, err := netip.ParsePrefix(u); err == nil {
			taken[a.Addr()] = true
			continue
		}
		if a, err := netip.ParseAddr(u); err == nil {
			taken[a] = true
		}
	}
	for a := pfx.Addr().Next(); pfx.Contains(a); a = a.Next() {
		// Skip the broadcast address of an IPv4 prefix.
		if a.Is4() && pfx.Bits() < 31 && isBroadcast(pfx, a) {
			continue
		}
		if !taken[a] {
			return a, pfx.Bits(), nil
		}
	}
	return netip.Addr{}, 0, fmt.Errorf("no free address left in %s (%d already assigned)", serverCIDR, len(taken)-1)
}

func isBroadcast(pfx netip.Prefix, a netip.Addr) bool {
	last := pfx.Masked().Addr().As4()
	host := uint32(1)<<(32-pfx.Bits()) - 1
	v := uint32(last[0])<<24 | uint32(last[1])<<16 | uint32(last[2])<<8 | uint32(last[3])
	v |= host
	return a.As4() == [4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

// nextPeerID returns an unused numeric id, matching the vendor's peer_<n> naming so its
// own UI still lists clients created here.
func nextPeerID(t *uciTree) int {
	max := 1000
	for _, s := range t.sectionsOfType("peers") {
		if n, err := strconv.Atoi(t.get(s, "peer_id")); err == nil && n > max {
			max = n
		}
	}
	return max + 1
}

// ------------------------------------------------------------------ config rendering

type wgClientConfig struct {
	PrivateKey   string
	Address      string
	DNS          string
	MTU          int
	ServerPubKey string
	AllowedIPs   string
	Endpoint     string
	Keepalive    int
}

func (c wgClientConfig) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\nPrivateKey = %s\nAddress = %s\n", c.PrivateKey, c.Address)
	if c.DNS != "" {
		fmt.Fprintf(&b, "DNS = %s\n", c.DNS)
	}
	if c.MTU > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", c.MTU)
	}
	fmt.Fprintf(&b, "\n[Peer]\nPublicKey = %s\nAllowedIPs = %s\nEndpoint = %s\n",
		c.ServerPubKey, c.AllowedIPs, c.Endpoint)
	if c.Keepalive > 0 {
		fmt.Fprintf(&b, "PersistentKeepalive = %d\n", c.Keepalive)
	}
	return b.String()
}

// renderQR draws the config as half-block characters, two module rows per text row, so a
// full config still fits a normal terminal. Medium recovery survives the font rendering
// and rounded corners a phone camera sees on a screen.
func renderQR(text string) (string, error) {
	q, err := qrcode.New(text, qrcode.Medium)
	if err != nil {
		return "", fmt.Errorf("encoding QR: %w", err)
	}
	return q.ToSmallString(false), nil
}

// ------------------------------------------------------------------ the tool

func (s *Server) wgNewClient(ctx context.Context, in wgNewClientIn) (string, string, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return "", "", fmt.Errorf("name is required")
	}

	show, err := run(ctx, defaultCmdTimeout, "uci", "show", "wireguard_server")
	if err != nil {
		return show, "", fmt.Errorf("reading wireguard_server config: %w", err)
	}
	t := parseUCIShow(show)

	server := in.Server
	if server == "" {
		servers := t.sectionsOfType("servers")
		if len(servers) != 1 {
			return "", "", fmt.Errorf("found %d server sections %v; pass 'server' to choose one", len(servers), servers)
		}
		server = servers[0]
	}
	if t.typ[server] != "servers" {
		return "", "", fmt.Errorf("%q is not a wireguard server section", server)
	}

	serverCIDR, serverPub, port := t.get(server, "address_v4"), t.get(server, "public_key"), t.get(server, "port")
	if serverCIDR == "" || serverPub == "" || port == "" {
		return "", "", fmt.Errorf("server %q is missing address_v4, public_key or port", server)
	}

	var used []string
	for _, p := range t.sectionsOfType("peers") {
		if ip := t.get(p, "client_ip"); ip != "" {
			used = append(used, ip)
		}
	}
	addr, bits, err := nextFreeClientIP(serverCIDR, used)
	if err != nil {
		return "", "", err
	}

	endpointHost := in.Endpoint
	if endpointHost == "" {
		if endpointHost, err = s.wgEndpoint(ctx); err != nil {
			return "", "", err
		}
	}
	if !strings.Contains(endpointHost, ":") {
		endpointHost += ":" + port
	}

	priv, err := run(ctx, defaultCmdTimeout, "wg", "genkey")
	if err != nil {
		return priv, "", fmt.Errorf("generating private key: %w", err)
	}
	priv = strings.TrimSpace(priv)
	pub, err := runStdin(ctx, defaultCmdTimeout, priv, "wg", "pubkey")
	if err != nil {
		return "", "", fmt.Errorf("deriving public key: %w", err)
	}
	pub = strings.TrimSpace(pub)

	cfg := wgClientConfig{
		PrivateKey:   priv,
		Address:      fmt.Sprintf("%s/%d", addr, bits),
		DNS:          orDefault(in.DNS, firstAddr(serverCIDR)),
		MTU:          orDefaultInt(in.MTU, 1420),
		ServerPubKey: serverPub,
		AllowedIPs:   orDefault(in.AllowedIPs, "0.0.0.0/0"),
		Endpoint:     endpointHost,
		Keepalive:    orDefaultInt(in.Keepalive, 25),
	}

	id := nextPeerID(t)
	sec := fmt.Sprintf("peer_%d", id)
	set := [][]string{
		{"set", "wireguard_server." + sec + "=peers"},
		{"set", "wireguard_server." + sec + ".name=" + name},
		{"set", "wireguard_server." + sec + ".peer_id=" + strconv.Itoa(id)},
		{"set", "wireguard_server." + sec + ".presharedkey_enable=0"},
		{"set", "wireguard_server." + sec + ".dns=" + cfg.DNS},
		{"set", "wireguard_server." + sec + ".allowed_ips=" + cfg.AllowedIPs},
		{"set", "wireguard_server." + sec + ".mtu=" + strconv.Itoa(cfg.MTU)},
		{"set", "wireguard_server." + sec + ".persistent_keepalive=" + strconv.Itoa(cfg.Keepalive)},
		{"set", "wireguard_server." + sec + ".public_key=" + pub},
		{"set", "wireguard_server." + sec + ".private_key=" + priv},
		{"set", "wireguard_server." + sec + ".client_ip=" + cfg.Address},
		{"set", "wireguard_server." + sec + ".deprecated=0"},
		{"set", "wireguard_server." + sec + ".enabled=1"},
	}
	for _, args := range set {
		if out, err := run(ctx, defaultCmdTimeout, append([]string{"uci"}, args...)...); err != nil {
			run(ctx, defaultCmdTimeout, "uci", "revert", "wireguard_server")
			return out, "", fmt.Errorf("staging peer: %w", err)
		}
	}
	if out, err := run(ctx, defaultCmdTimeout, "uci", "commit", "wireguard_server"); err != nil {
		return out, "", fmt.Errorf("committing peer: %w", err)
	}

	// Hot-add so established sessions survive. A failure here is not fatal: the peer is
	// committed and will exist after the next interface restart, so say so rather than
	// implying nothing happened.
	warn := ""
	iface, err := s.wgInterfaceFor(ctx, server)
	if err != nil {
		warn = "\n\nNOTE: could not identify the running interface (" + err.Error() +
			"). The peer is saved but will not work until the WireGuard server restarts."
	} else if out, err := run(ctx, defaultCmdTimeout, "wg", "set", iface,
		"peer", pub, "allowed-ips", addr.String()+"/32"); err != nil {
		warn = "\n\nNOTE: the peer is saved but could not be added to the running interface (" +
			strings.TrimSpace(out) + "). It will work after the WireGuard server restarts."
	}

	body := fmt.Sprintf("Created client %q as %s at %s.\n\n%s\n%s%s",
		name, sec, cfg.Address, cfg.String(), qrOrNote(cfg.String()), warn)
	// Summary is audited; the config and key are not. Keep both out of it.
	return body, fmt.Sprintf("created wireguard client %q (%s) at %s", name, sec, cfg.Address), nil
}

func qrOrNote(conf string) string {
	qr, err := renderQR(conf)
	if err != nil {
		return "(QR could not be rendered: " + err.Error() + " -- use the text config above)"
	}
	return "Scan with the WireGuard app:\n\n" + qr
}

// wgEndpoint picks the address clients should dial: the router's dynamic-DNS name if it
// has one, otherwise its current WAN address. A dynamic WAN address baked into a client
// config stops working at the next reconnect, so the name is preferred.
func (s *Server) wgEndpoint(ctx context.Context) (string, error) {
	if out, err := run(ctx, defaultCmdTimeout, "uci", "show", "gl_ddns"); err == nil {
		t := parseUCIShow(out)
		for _, sec := range t.order {
			if t.get(sec, "enabled") == "1" && t.get(sec, "domain") != "" {
				return t.get(sec, "domain"), nil
			}
		}
	}
	out, err := run(ctx, defaultCmdTimeout, "ubus", "call", "network.interface.wan", "status")
	if err == nil {
		if ip := firstJSONIPv4(out); ip != "" {
			return ip, nil
		}
	}
	return "", fmt.Errorf("could not determine a WAN endpoint; pass 'endpoint' explicitly")
}

// wgInterfaceFor finds the network interface whose proto config points at this server
// section, which is what `wg set` needs to name.
func (s *Server) wgInterfaceFor(ctx context.Context, server string) (string, error) {
	out, err := run(ctx, defaultCmdTimeout, "uci", "show", "network")
	if err != nil {
		return "", err
	}
	t := parseUCIShow(out)
	var candidates []string
	for _, sec := range t.order {
		if t.get(sec, "config") == server && strings.Contains(t.get(sec, "proto"), "wg") {
			candidates = append(candidates, sec)
		}
	}
	sort.Strings(candidates)
	if len(candidates) == 0 {
		return "", fmt.Errorf("no network interface references server %q", server)
	}
	return candidates[0], nil
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

func orDefaultInt(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}

// firstAddr returns the bare address of a CIDR, e.g. "10.1.0.1/24" -> "10.1.0.1".
func firstAddr(cidr string) string {
	if pfx, err := netip.ParsePrefix(cidr); err == nil {
		return pfx.Addr().String()
	}
	return ""
}

// firstJSONIPv4 pulls the first "address":"a.b.c.d" out of ubus JSON without pulling in a
// full parse of a shape that varies between releases.
func firstJSONIPv4(s string) string {
	const key = `"address":`
	for i := strings.Index(s, key); i >= 0; i = strings.Index(s, key) {
		s = s[i+len(key):]
		q1 := strings.Index(s, `"`)
		if q1 < 0 {
			return ""
		}
		q2 := strings.Index(s[q1+1:], `"`)
		if q2 < 0 {
			return ""
		}
		cand := s[q1+1 : q1+1+q2]
		if a, err := netip.ParseAddr(cand); err == nil && a.Is4() {
			return cand
		}
	}
	return ""
}
