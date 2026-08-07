package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

// openwrt-mcp -- an MCP server hosted on an OpenWrt router.
// Copyright (C) 2026 Ian Williams
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU Affero General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option) any
// later version. See the LICENSE file, or <https://www.gnu.org/licenses/>.

var version = "0.4.0"

const sourceURL = "https://github.com/GlassOnTin/openwrt-mcp"

const (
	defaultConfigPath = "/etc/config/openwrt-mcp"
	defaultStatePath  = "/etc/openwrt-mcp"
)

func randToken() string {
	b := make([]byte, 9)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprint(time.Now().UnixNano())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func main() {
	log.SetFlags(0)
	configPath := flag.String("config", defaultConfigPath, "path to the UCI config file")
	statePath := flag.String("state", defaultStatePath, "directory for tokens, audit log and pending state")
	flag.Usage = usage
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}

	switch args[0] {
	case "serve":
		s, err := NewServer(*configPath, *statePath)
		must(err)
		must(s.Serve())

	case "pair":
		if len(args) != 2 {
			die("usage: openwrt-mcp pair <client-name>")
		}
		ts, err := LoadTokens(*statePath + "/tokens")
		must(err)
		raw, err := ts.Mint(args[1])
		must(err)
		// Printed once and never recoverable: only the SHA-256 digest is stored.
		fmt.Println(raw)

	case "unpair":
		if len(args) != 2 {
			die("usage: openwrt-mcp unpair <client-name>")
		}
		ts, err := LoadTokens(*statePath + "/tokens")
		must(err)
		fmt.Printf("revoked %d token(s) for %q\n", ts.Revoke(args[1]), args[1])

	case "clients":
		ts, err := LoadTokens(*statePath + "/tokens")
		must(err)
		for _, c := range ts.Clients() {
			fmt.Println(c)
		}

	case "allow":
		if len(args) != 5 {
			die("usage: openwrt-mcp allow <client> <tool[,tool...]> <scope-glob[ scope-glob...]> <duration|never>\n" +
				"  e.g. openwrt-mcp allow claude-code ubus_call 'network.* iwinfo.*' 30d")
		}
		must(appendPolicy(*configPath, args[1], args[2], args[3], args[4]))
		fmt.Printf("granted %s -> %s on '%s' for %s\nrestart to apply: /etc/init.d/openwrt-mcp restart\n",
			args[1], args[2], args[3], args[4])

	case "policies":
		cfg, err := LoadConfig(*configPath)
		must(err)
		if len(cfg.Policies) == 0 {
			fmt.Println("(none -- every gated tool is denied)")
		}
		for _, p := range cfg.Policies {
			exp := "never"
			if !p.Expires.IsZero() {
				exp = p.Expires.Format(time.RFC3339)
				if time.Now().After(p.Expires) {
					exp += " (EXPIRED)"
				}
			}
			state := ""
			if !p.Enabled {
				state = " [disabled]"
			}
			fmt.Printf("%s%s\n  tools:  %s\n  scopes: %s\n  rate:   %d/min\n  expires:%s\n",
				p.Client, state, strings.Join(p.Tools, ", "), strings.Join(p.Scopes, " "), p.MaxPerMin, exp)
		}

	case "mfa":
		// Enrolment is CLI-only for the same reason pair/allow are: the secret is credential
		// material, and nothing reachable over the network should be able to mint or read it.
		ms, err := LoadMFA(*statePath + "/mfa")
		must(err)
		sub := ""
		if len(args) > 1 {
			sub = args[1]
		}
		switch sub {
		case "enrol", "enroll":
			if len(args) != 3 {
				die("usage: openwrt-mcp mfa enrol <client>")
			}
			secret, uri, err := ms.Enrol(args[2], "openwrt-mcp")
			must(err)
			// Printed once, like a pairing token -- but unlike one this IS recoverable from
			// the state file, so say plainly that the file is credential material.
			fmt.Printf("Enrolled %q. Scan this in your authenticator app:\n\n  %s\n\n"+
				"  secret: %s\n\n"+
				"Then require it for the tools that matter, e.g. in %s:\n"+
				"  list mfa_tools 'exec'\n"+
				"  list mfa_tools 'uci_apply'\n"+
				"  option mfa_window '15m'\n\n"+
				"Restart to apply: /etc/init.d/openwrt-mcp restart\n"+
				"The secret is stored at %s/mfa (mode 0600); anyone who reads it can generate codes.\n",
				args[2], uri, secret, defaultConfigPath, *statePath)

		case "status", "":
			clients := ms.Clients()
			if len(clients) == 0 {
				fmt.Println("(no clients enrolled -- no tool requires a second factor)")
			}
			for _, c := range clients {
				fmt.Printf("%s: enrolled\n", c)
			}
			cfg, err := LoadConfig(*configPath)
			must(err)
			for _, p := range cfg.Policies {
				if len(p.MFATools) > 0 {
					fmt.Printf("  policy %s requires a code for: %s (window %s)\n",
						p.Client, strings.Join(p.MFATools, ", "), p.MFAWindow)
					if !ms.Enrolled(p.Client) {
						fmt.Printf("  WARNING: %q has no enrolled secret, so those tools cannot be unlocked.\n"+
							"           Run: openwrt-mcp mfa enrol %s\n", p.Client, p.Client)
					}
				}
			}

		default:
			die("usage: openwrt-mcp mfa enrol <client> | openwrt-mcp mfa status")
		}

	case "status":
		// Backs the router's own web UI via the oui-httpd RPC module; --json is the
		// machine-readable form of exactly what the text output shows.
		fs := flag.NewFlagSet("status", flag.ExitOnError)
		asJSON := fs.Bool("json", false, "emit JSON")
		lines := fs.Int("audit", 20, "how many recent audit entries to include (0 for none)")
		must(fs.Parse(args[1:]))
		must(runStatus(*configPath, *statePath, *lines, *asJSON))

	case "version":
		fmt.Printf("openwrt-mcp %s\n", version)

	default:
		die("unknown command %q", args[0])
	}
}

// appendPolicy adds a policy block to the UCI config. Grant management is CLI-only and is
// deliberately not exposed as an MCP tool, so there is no tool for a policy to cover and
// therefore no self-escalation path through the policy system itself.
func appendPolicy(configPath, client, tools, scopes, duration string) error {
	var expires string
	if duration != "never" {
		d, err := parseDuration(duration)
		if err != nil {
			return err
		}
		expires = time.Now().Add(d).Format(time.RFC3339)
	}
	var b strings.Builder
	b.WriteString("\nconfig policy\n")
	fmt.Fprintf(&b, "\toption client\t'%s'\n", client)
	for _, t := range strings.Split(tools, ",") {
		if t = strings.TrimSpace(t); t != "" {
			fmt.Fprintf(&b, "\tlist tools\t'%s'\n", t)
		}
	}
	for _, sc := range strings.Fields(scopes) {
		fmt.Fprintf(&b, "\tlist scopes\t'%s'\n", sc)
	}
	if expires != "" {
		fmt.Fprintf(&b, "\toption expires\t'%s'\n", expires)
	}
	b.WriteString("\toption enabled\t'1'\n")

	f, err := os.OpenFile(configPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(b.String())
	return err
}

// parseDuration extends time.ParseDuration with 'd' for days, since grants are
// naturally expressed in days and Go's parser stops at hours.
func parseDuration(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		var days float64
		if _, err := fmt.Sscanf(strings.TrimSuffix(s, "d"), "%f", &days); err != nil {
			return 0, fmt.Errorf("bad duration %q", s)
		}
		return time.Duration(days * 24 * float64(time.Hour)), nil
	}
	return time.ParseDuration(s)
}

func usage() {
	fmt.Fprintf(os.Stderr, `openwrt-mcp %s -- an MCP server hosted on the router

  serve                                       run the daemon (loopback only)
  pair     <client>                           mint a bearer token, printed once
  unpair   <client>                           revoke every token for a client
  clients                                     list paired clients
  allow    <client> <tools> <scopes> <dur>    grant a standing policy
  revoke                                      (edit %s and restart)
  policies                                    show current grants
  status   [--json] [--audit N]                daemon state, pairings, grants, recent audit
  mfa      enrol <client> | status           optional TOTP second factor for gated tools
  version

Reach it from a workstation with:
  ssh -N -L 8730:127.0.0.1:8730 root@router
`, version, defaultConfigPath)
	flag.PrintDefaults()
}

func must(err error) {
	if err != nil {
		log.Fatalf("openwrt-mcp: %v", err)
	}
}

func die(format string, a ...any) {
	log.Fatalf("openwrt-mcp: "+format, a...)
}
