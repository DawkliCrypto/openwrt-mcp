# Changelog

## v0.4.0

**An optional TOTP second factor for the tools that can change or read anything.** Opt-in per
policy — absent means off, so every existing configuration behaves exactly as before.

### Added

- `mfa_tools` and `mfa_window` on a policy. Naming a tool there additionally requires an
  unexpired TOTP unlock; `'*'` covers every tool the policy grants.
- `openwrt-mcp mfa enrol <client>` prints a QR-scannable `otpauth://` URI once, and
  `openwrt-mcp mfa status` shows who is enrolled and what is gated.
- An `mfa_unlock` tool taking a 6-digit code.

### Why a window rather than a code per call

A broad grant plus a stolen bearer token is root on the router. The token is something the
workstation has; a TOTP code is something the operator has, elsewhere.

But an agent works in bursts, and a control that demands six digits per call gets switched
off — a control too annoying to leave on protects nothing. So one code opens a time-boxed
window and the gated tools work normally until it lapses, the way `sudo` does.

### Decisions worth knowing

- `mfa_unlock` is itself ungated, or satisfying the factor would deadlock behind the factor.
  Safe because it grants nothing without a valid current code.
- The check runs **after** authorisation, so an unauthorised caller learns nothing about which
  tools are gated.
- Unenrolled and wrong-code fail with identical text; distinguishing them tells an attacker
  which clients are worth attacking.
- Codes are single-use. Without that a code is good for its whole ~90-second acceptance span.
- Unlocks live in memory only, so a restart re-locks everything.
- `mfa_tools` naming a tool the policy does not grant is rejected at load — a typo would
  otherwise sit there looking like protection.
- The secret is stored recoverably, because TOTP is symmetric, unlike bearer tokens which are
  kept only as digests. Hence mode 0600, and `enrol` is CLI-only. **Run it yourself**: a
  secret that passes through anyone else is not a second factor.

### Fixed before release

- A freshly enrolled client was rejected with "invalid code" on a **running** daemon. The
  secret file was read once at startup, and `mfa enrol` is a separate process writing it, so
  enrolment silently needed a restart. It now reloads on change, the way `allow` already did.
  Rotating a secret closes any window opened under the old one.
- The `otpauth://` account now names the router (`claude-code@GL-BE14000`). Without it, two
  routers produce identical authenticator entries and the only way to pair them up is trying
  each code against each router — which is precisely how this was found.

### Verified

End to end on hardware: `exec` denied, a real code unlocked for 15m, `exec` worked, the same
code was refused as replayed, and `ubus_call` — not listed in `mfa_tools` — was unaffected
throughout.

76 tests. TOTP is checked against RFC 6238's own vectors, because a hand-rolled
implementation that is subtly wrong still agrees with itself: enrolment and unlock would
match while no real authenticator app could produce an accepted code. Nine mutations all
killed, including gate-always-allows, accepts-any-code, replay-removed, window-never-expires,
reload-removed and 0600→0644.

## v0.3.2

**Fixes a bug that hid the status page on any router not in "router" net mode.** Worth
upgrading if you run GL.iNet firmware and the page never appeared.

### Fixed

- `menu.d/openwrt-mcp.json` declared `show_mode: ["router"]`, copied from AdGuard Home
  without checking whether it applied. It does not: openwrt-mcp exposes `ubus` and `uci`,
  which exist in every net mode, so there is no mode in which the daemon runs but its status
  page should be invisible. The key is now omitted, matching `plugins`, and the page appears
  in every mode.

Found by installing on a second device — a Slate 7 Pro (GL-BE10000) running firmware 4.8.4
in **ap** mode. Everything worked except the visible part: the package installed, the RPC
answered, `ui.get_menu_list` returned the entry and the view was served, but the nav had no
item. AdGuard Home, Tailscale and ZeroTier were missing too — all declaring
`show_mode: ["router"]` — so the SPA was faithfully honouring a declaration that was wrong.

### Verified

The published `.ipk` installed unchanged on the Slate 7 Pro: different SoC (mt7987 vs
mt7988), different firmware (4.8.4 vs 4.9.0), same `aarch64_cortex-a53`. Auth matrix, scope
gate, response pruning, the RPC module and its access gate all behaved as on the Flint 4, and
the page now renders in both router and ap mode.

## v0.3.1

Documentation only — **no functional change from v0.3.0**, so there is no reason to upgrade
unless you want the version string to match. The binary differs only in that string.

- README now leads with a screenshot of the MCP Server page in GL.iNet's admin panel,
  captured from a real Flint 4 rather than mocked up.
- The screenshot shows the recommended *narrow* grant, and its audit tail includes a genuine
  refusal — `ubus_call` on `dnsmasq.metrics` denied against scopes covering `network.*`,
  `iwinfo.*`, `system.*` and `gl-clients.*`, with the `allow` line that would cover it. An
  earlier capture showed `scope: *`, which contradicted the README's own advice to start
  narrow.

## v0.3.0

A status page inside the router's own web UI, under **Applications → MCP Server**: daemon
state, paired clients, standing policies and the recent audit tail. Read-only.

### Added

- `openwrt-mcp status [--json] [--audit N]` — daemon state, pairings, grants and recent
  audit entries. `--json` is what the web UI consumes.
- An oui-httpd RPC module at `/usr/lib/oui-httpd/rpc/openwrt-mcp` exposing
  `openwrt-mcp.status`, plus the view and menu entry the GL.iNet SPA loads.

### Why the UI is read-only

`pair`, `allow` and `unpair` stay command-line only, so nothing reachable over the network
can widen a grant — the same property that keeps them out of the MCP tool list. The page
shows and explains grants; it never issues them.

Status is a CLI subcommand rather than a second HTTP endpoint for the same reason. The
daemon's only listener is loopback and reachability is explicitly not treated as identity,
so a second HTTP surface would mean either exposing policy and audit data to every process
on the router, or storing a bearer token on the router for the UI to present. oui-httpd
already runs as root and can read the state directory anyway, so a CLI read grants its
caller nothing new.

### Notes for anyone building a GL.iNet view

No GL.iNet SDK or bundler is needed. The SPA fetches a view as text, `eval`s it, and uses
the resulting value as the route component, so a plain IIFE returning a Vue 2 options object
is sufficient. The shipped views' `module.exports=…` form works only because a direct `eval`
inherits the enclosing webpack wrapper's scope. Vue is 2.6.12, so render functions avoid
needing a template compiler at eval time.

`running` in the report asks `/health` and requires the daemon to identify itself, rather
than just dialling the port — 8730 is an ordinary port for something else to hold, and an
`ssh -L` answers it happily.

## v0.2.0

First release with a downloadable package. The `.ipk` on the release page installs without a
Go toolchain or the OpenWrt SDK.

Verified on a GL.iNet Flint 4 (GL-BE14000), OpenWrt 21.02-SNAPSHOT / GL firmware 4.9.0.

### It installs on someone else's machine now

`v0.1.0` could not be installed by anyone but the author:

- `Makefile` hardcoded `GO ?= /usr/local/go/bin/go`, so Go from apt, brew or asdf failed
  with `make: *** Error 127` on the first command.
- The `files/` tree — the procd init script and the default UCI config — had **never been
  committed**. An unanchored `.gitignore` pattern swallowed it, so a fresh clone could not
  run `make install` at all.
- SSH key auth was assumed but never documented, while `make install` pipes over
  non-interactive ssh and a factory router has no `authorized_keys`.
- `$TOK` appeared in the connect instructions and was never defined.

### Added

- `.ipk` packaging. The daemon survives a firmware upgrade via `/lib/upgrade/keep.d`, and
  `/etc/config/openwrt-mcp` is a conffile so upgrades never clobber live policies.
- `uci_apply` creates and deletes whole sections, not just options. A change with `type` and
  no `option` creates a named section; `delete` with no `option` removes one. Adding a static
  lease or a firewall rule is now one rollback-armed call rather than a root shell.
  Section-level changes take the scope `<config>.<section>`, distinct from
  `<config>.<section>.<option>`.
- Response pruning for oversized ubus replies. `gl-clients list` measured 100,587 bytes on a
  49-client network; replies over 8 KB now have arrays capped at 16 elements, pruned from the
  decoded tree so the result stays valid JSON. That call is now 43,676 bytes.
- CI: vet, tests, cross-build, and assertions that the package contains the four files the
  router needs and declares its conffile.

### Fixed

- `make install` failed with `ETXTBSY` on every install after the first — `cat >` cannot
  overwrite a running executable. It now writes a sidecar and renames.
- Pruning no longer touches replies small enough to read whole. The first version capped a
  17-element list in 196 bytes (`iwinfo devices`), discarded a real interface and made the
  reply longer.

### Documented

Findings from the Flint 4 `gl-*` surface, including why `gl_screen.*` should not be granted
(its ubus `set` bypasses the Lua validation layer and corrupts the value type) and that the
screen passcode is stored in plaintext under `/tmp`.

### Known limitations

The `.ipk` targets `opkg`. Stock OpenWrt 24.10+ moved to `apk` and is untested; GL.iNet
firmware 4.x is opkg-based, so this does not affect the Flint range.

## v0.1.0

Initial implementation: resident MCP server under procd, six generic tools over `ubus`/`uci`,
bearer auth, standing policies with deny-by-default, audit log, and `uci_apply` rollback.
Written against a GL.iNet Flint 2.
