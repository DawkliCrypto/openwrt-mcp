# openwrt-mcp

An MCP server that runs **on** an OpenWrt router, so Claude Code (or any MCP client) can
inspect and change it over an SSH tunnel.

Developed against **GL.iNet** routers — verified on a Flint 2 and a Flint 4 (GL-BE14000).
GL.iNet firmware 4.x is OpenWrt 21.02 with `opkg`, which is what the `.ipk` targets. It
should suit any `opkg`-based OpenWrt; stock OpenWrt 24.10+ moved to `apk` and is **untested**.

The other OpenWrt MCP servers I could find run *off*-router — they SSH in from your
workstation on every call. This one is resident: a single static Go binary under procd,
always on, with its own authorisation and audit trail.

It exposes six generic tools rather than a hand-written catalogue of router features.
`ubus list -v` already self-describes every object, method and argument signature on the
box, so the agent discovers what your router can actually do instead of trusting a list
that goes stale with each firmware update. On a GL.iNet box that means the vendor's own
`gl-*` objects come through without a line of code per feature.

![The MCP Server page in GL.iNet's admin panel: daemon status, paired clients, standing
policies and the recent audit tail, including a refused call](docs/router-ui.png)

On GL.iNet firmware it adds a read-only page to the router's own admin panel, under
**Applications → MCP Server** — what is running, who is paired, what they may do, and what
they have been doing. Granting stays on the command line.

The refusal in that audit tail is the security model working, not a fault: `ubus_call` was
granted on `network.*`, `iwinfo.*`, `system.*` and `gl-clients.*`, so `dnsmasq.metrics` was
denied — and the denial names the uncovered scope and prints the `allow` line that would
cover it. Starting narrow costs little when widening is one command away.

---

## Use cases

### 1. Putting a new router through its paces

The one this was written for. Ask in plain language and let the agent find the objects:

> "What's on the 6GHz radio right now, and how much airtime is each client using?"

The agent calls `ubus_list` to see what's available (`iwinfo`, `network.wireless`,
`luci-rpc`, `gl-clients` …), then `ubus_call` to read them. A read-only grant covers this
and cannot change anything:

```sh
openwrt-mcp allow claude-code ubus_call,logread 'network.* iwinfo.* luci-rpc.* gl-*' 30d
```

### 2. "The wifi has been dropping out"

Correlating a symptom across sources is tedious by hand and well suited to an agent:
association lists, survey/scan data, DHCP lease churn and the system log, over the same
window. Still a read-only grant — worth having standing, since it can't break anything.

> "Cross-reference the last hour of logs against which clients disconnected, and tell me
> whether it correlates with a channel change or a DFS event."

### 3. Config changes with an undo you don't have to remember

The interesting one. `uci_apply` stages your changes, snapshots the configs it's touching,
commits, reloads — and **arms a rollback timer**. If `uci_confirm` isn't called before it
expires, the router puts everything back. Lock yourself out with a bad firewall rule and it
repairs itself while you're still typing.

```
uci_apply  {"changes": [{"config":"firewall","section":"@zone[1]","option":"input","value":"DROP"}],
            "timeout": 120}
  -> "ROLLBACK ARMED: reverts at 15:07:22Z (in 2m0s) unless you call uci_confirm {...}"

  ... you check you can still reach the router ...

uci_confirm {"token": "3Kc681oIe4IP"}
  -> "Confirmed. Rollback cancelled."
```

A change with `type` and no `option` **creates** a section, so whole objects go in under one
rollback. Pinning a DHCP lease is one call:

```
uci_apply {"changes": [
  {"config":"dhcp","section":"raspberrypi","type":"host"},
  {"config":"dhcp","section":"raspberrypi","option":"mac","value":"88:a2:9e:8a:e4:15"},
  {"config":"dhcp","section":"raspberrypi","option":"ip","value":"192.168.0.141"},
  {"config":"dhcp","section":"raspberrypi","option":"network","value":"lan"}]}
```

Changes run in order, so the creating change comes first. `delete` with no `option` removes
the whole section. Sections are **named**, not `uci add` anonymous ones: later changes in the
same batch can refer to the name, and re-running an apply is idempotent where `uci add` would
append a duplicate every time.

If the daemon is restarted mid-window the change is rolled back on startup, because nobody
ever vouched for it.

### 4. An audit trail for what the agent did

Every tool call is recorded at the wrapper, so a new tool is logged without opting in.
`DENIED` is a distinct outcome from `ERROR` — "we said no" isn't "it broke":

```
OK      uci_apply    system.@system[0].description   applied 1 change(s), rollback armed 20s
OK      uci_rollback -                               rolled back system (timeout)
DENIED  uci_apply    system.@system[0].description   denied: no policy grants uci_apply to "confirm-test"
OK      uci_confirm  -                               confirmed m2_glAwWSd5L
```

Secrets are redacted by the recorder rather than by callers, so a new tool can't leak a
password by forgetting to scrub it. `keyId` and `publicKey` deliberately survive — they're
identifiers, and redacting them would make the log useless.

---

## Install

`ROUTER` below is your router's LAN address. GL.iNet ships `192.168.8.1`; change it if you
have. Everything is `root@`, because that is the only account OpenWrt has.

### 1. Set up SSH key auth (required)

The install pipes over `ssh` non-interactively, so password auth is not enough. A factory
router has no `authorized_keys` yet:

```sh
ssh-keygen -f ~/.ssh/known_hosts -R 192.168.8.1   # only if that IP held another device before
ssh-copy-id root@192.168.8.1                      # asks for the router password, once
ssh root@192.168.8.1 true                         # must succeed with no prompt
```

Leave the router's password auth enabled — it is your way back in if the key is ever lost.

### 2. Install the daemon

Download `openwrt-mcp_*.ipk` from [Releases](https://github.com/GlassOnTin/openwrt-mcp/releases)
and push it over — no toolchain needed:

```sh
ssh root@192.168.8.1 'cat > /tmp/openwrt-mcp.ipk' < openwrt-mcp_0.3.0_aarch64_cortex-a53.ipk
ssh root@192.168.8.1 'opkg install /tmp/openwrt-mcp.ipk && rm -f /tmp/openwrt-mcp.ipk'
```

Or build it yourself — needs **Go 1.26+** on your workstation, nothing on the router:

```sh
make install-ipk ROUTER=root@192.168.8.1   # packaged; survives a firmware upgrade
make install     ROUTER=root@192.168.8.1   # straight onto the filesystem, no packaging
```

The router needs no Go, no compiler and no OpenWrt SDK: the binary is statically linked and
cross-compiled on your machine. `make` uses whatever `go` is on your PATH; override with
`make install-ipk GO=/usr/local/go/bin/go` if you keep it somewhere unusual.

### 3. Pair a client and grant it something

`pair` prints the token **once** — capture it, it is not recoverable:

```sh
TOK=$(ssh root@192.168.8.1 'openwrt-mcp pair claude-code')
ssh root@192.168.8.1 "openwrt-mcp allow claude-code ubus_list,ubus_call,logread 'network.* iwinfo.* system.*' 30d"
```

Nothing is granted by default. Start narrow: a refusal names the uncovered scope and prints
the exact `allow` line that would widen it, so it is cheap to loosen and expensive to notice
you were too loose.

### 4. Connect over a tunnel

The daemon refuses to bind anything but loopback, so reach it through SSH:

```sh
ssh -N -f -L 8730:127.0.0.1:8730 root@192.168.8.1
claude mcp add --transport http openwrt http://127.0.0.1:8730/mcp \
  --header "Authorization: Bearer $TOK"
```

Pick a different local port if 8730 is taken on your workstation — `-L 8731:127.0.0.1:8730`,
and point the client at 8731 to match.

To keep the tunnel up across reboots and drops, run it under systemd rather than by hand:

```ini
# ~/.config/systemd/user/openwrt-mcp-tunnel.service
[Unit]
Description=SSH tunnel to openwrt-mcp
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/ssh -NT -o BatchMode=yes -o ExitOnForwardFailure=yes \
    -o ServerAliveInterval=30 -o ServerAliveCountMax=3 \
    -L 8730:127.0.0.1:8730 root@192.168.8.1
Restart=always
RestartSec=10
StartLimitIntervalSec=0

[Install]
WantedBy=default.target
```

```sh
systemctl --user enable --now openwrt-mcp-tunnel
```

No `autossh` needed: `Restart=always` handles respawn, and the `ServerAlive` options plus
`ExitOnForwardFailure` cover the case autossh exists for — a connection that is up but dead.

> OpenWrt's dropbear has no `sftp-server`, so plain `scp` fails with "Connection closed".
> The Makefile pipes over ssh instead; use `scp -O` if you're copying files by hand.

### Packaging notes

`mkipk.sh` builds the `.ipk` without the OpenWrt SDK — the binary is `CGO_ENABLED=0` static
Go, so there is nothing to cross-link and only the archive format is left. Two details cost
real time, both verified on opkg 1bf042dd (2021-06-13):

- **The container is a gzipped tar, not an `ar` archive.** `.ipk` exists in both forms and
  most documentation describes the `ar` one (identical to `.deb`). This opkg rejects `ar`
  with `pkg_init_from_file: Malformed package file` — both binutils' output *and* hand-written
  headers without binutils' trailing-slash name quirk.
- **`/etc/config/openwrt-mcp` is declared a conffile**, so an upgrade never clobbers live
  policies or pairings; opkg parks the new default at `…-opkg` instead.

The package also ships `/lib/upgrade/keep.d/openwrt-mcp`, which is how the binary, the init
script and the token store survive `sysupgrade`. GL.iNet's own packages use the same
mechanism.

---

## The router's own web UI

On GL.iNet firmware the package adds a page under **Applications → MCP Server**: whether the
daemon is running, which clients are paired, what each is granted, and the recent audit tail.

It is **read-only**. `pair`, `allow` and `unpair` stay command-line only, so nothing
reachable over the network can widen a grant — the same reason they are not MCP tools. The
page explains grants; it never issues them.

The data comes from `openwrt-mcp status --json` via an oui-httpd RPC module
(`openwrt-mcp.status`). Status is a CLI subcommand rather than a second HTTP endpoint on
purpose: the daemon's only listener is loopback and reachability is not treated as identity,
so another HTTP surface would mean either exposing policy and audit data to every process on
the router, or keeping a bearer token on the router for the UI to present. oui-httpd already
runs as root and can read the state directory, so a CLI read grants its caller nothing new.

On stock OpenWrt the two extra files are inert — nothing reads them — so it stays one package.

> Building a view for this UI needs no GL.iNet SDK and no bundler. The SPA fetches the file
> as text, `eval`s it, and uses the resulting value as the route component, so a plain IIFE
> returning a Vue 2 options object is enough. The shipped `module.exports=…` bundles work only
> because a direct `eval` inherits the enclosing webpack wrapper's scope. Vue is 2.6.12, so
> render functions avoid needing a template compiler at eval time. See `ui/view.js`.

---

## Security model

Adapted from [Haven](https://github.com/GlassOnTin/Haven)'s MCP backbone.

| | |
|---|---|
| **Reachability** | Loopback only, enforced in code — startup fails on a routable address. SSH key auth is the outer lock, the bearer token the inner one. |
| **No loopback auto-trust** | Any process on the router can reach `127.0.0.1`, and `ssh -R` can make remote traffic arrive there. Reachability is never treated as identity; origin is recorded for attribution only. |
| **Tokens** | 256-bit, base64url, shown once. Only the SHA-256 digest is stored (mode 0600), compared in constant time. `unpair` takes effect without a restart. |
| **Authorisation** | Standing policies in `/etc/config/openwrt-mcp`. Deny by default. A policy grants a client a tool list, scope globs, a calls/minute ceiling and an expiry — and can only ever *add* permission. |
| **Refusals are actionable** | A denial names the uncovered scope and prints the `openwrt-mcp allow …` line that would grant it. |
| **Grant management is CLI-only** | `pair`/`allow`/`unpair` are not MCP tools, so there's no tool for a policy to cover and no self-escalation path through the policy system. |
| **Rollback** | `uci_apply` reverts unless confirmed, including across a daemon restart. |

`ubus_list` is the one ungated tool: introspection returns method names and argument types,
never configuration data, and without it an agent can't discover what to ask for.

### Why not rpcd's ACLs or its own apply/rollback?

Both were the first choice; neither works for a resident daemon.

- **rpcd ACLs don't apply.** A root process calling ubus over the local unix socket bypasses
  them entirely — sessionless `uci get` returns data. ACLs only bind the uhttpd JSON-RPC
  path. Relying on them here would be theatre.
- **rpcd's `uci apply {"rollback":true}` needs credentials.** Every uci *write* method takes
  a `ubus_rpc_session`, and `session.login` wants a username and password. Verified on
  OpenWrt 21.02 / rpcd 2022-02-19:

  ```
  ubus call uci apply '{}'                          -> Invalid argument   (no session)
  ubus call uci apply '{"ubus_rpc_session":"0..0"}' -> No response        (null session, no write ACL)
  ```

  Storing the router's root password in a file on the router is a worse hole than the one
  the rollback closes, so `uci_apply` snapshots and restores itself.

---

## Tools

| Tool | Policy scope | |
|---|---|---|
| `ubus_list` | *(ungated)* | Objects, methods and argument signatures. The discovery tool. |
| `ubus_call` | `<object>.<method>` | The workhorse: netifd, wireless, dnsmasq, iwinfo, luci-rpc, `gl-*`. Replies over 8 KB have long arrays pruned — see Findings. |
| `uci_apply` | `<config>.<section>.<option>`, or `<config>.<section>` for a section-level change | Stage → snapshot → commit → reload, rollback armed. Sets options, and creates or deletes whole sections. All scopes must be covered by one policy. |
| `uci_confirm` | *(tool-level)* | Cancels the rollback timer. |
| `exec` | `argv[0]` | Direct exec, **no shell** — no pipes, globs or redirection, and no quoting surface. |
| `logread` | *(tool-level)* | Split out from `exec` so logs can be granted without a root shell. |

---

## Status

Written against a GL.iNet **Flint 2**, now also verified on a **Flint 4** (GL-BE14000,
MT7988A, 2GB/64GB). The Flint 4 turned out to run the *same* base — OpenWrt 21.02-SNAPSHOT,
kernel 5.4.281, `aarch64_cortex-a53`, GL firmware 4.9.0 — so uci, ubus, procd and dropbear
behave identically and only the vendor `gl-*` layer differs.

**Verified on the Flint 4:** a real static DHCP lease pinned end to end — one `uci_apply`
deleting an anonymous `@host[2]`, creating a named `host` section and setting four options,
verified against dnsmasq's generated `dhcp-host=` line and a DNS lookup before confirming;
bearer auth (401 missing, 401 wrong, 200 valid, all three in the
audit log); the scope gate refusing an out-of-scope object *and* printing the `allow` line
that would grant it; `uci_apply` rollback-on-timeout restoring `/etc/config/system`
byte-identically against an independent `sha256sum` baseline; `uci_confirm` cancelling the
timer (value survived 25s past a 15s deadline, snapshot cleaned up); `exec` running a granted
`argv[0]`, refusing an ungranted one, and passing `|` through as a literal argument rather
than a pipe; `.ipk` install, conffile preservation and service enable via postinst; and the
whole path over a real `ssh -L` tunnel.

**Verified previously on the Flint 2 and not re-run here:** revocation taking effect without
a restart, per-client policy isolation.

29 unit tests pass. They're mutation-checked: neutering `Authorise` fails 5, neutering
`redact` fails 2, neutering the response pruner fails 2, and removing the pruner *call* from
`ubus_call` fails 1 — that last test exists because an earlier version of the pruner had
working unit tests while nothing asserted the tool actually used it.

**Not verified:** that `keep.d` survives a real `sysupgrade` — the file is installed and
correct, but no firmware flash was performed. Concurrency beyond one apply at a time
(a second `uci_apply` is refused while one is pending).

### Findings from the Flint 4 `gl-*` surface

- **`gl-clients list` is enormous.** With 49 clients attached it returned 100,587 bytes —
  60 samples of `last_rx` and 60 of `last_tx` per client. `ubus_call` now caps arrays at 16
  elements in the decoded reply, which brought that call to 43,676 bytes and left it valid
  JSON. Still not small; the remaining bulk is one legitimate row per client.
- **Pruning applies only to replies over 8 KB, and only when it actually shrinks them.**
  Both conditions were added after the first version got it wrong: `ubus call iwinfo devices`
  returns 17 radio interface names in 196 bytes, and capping that at 16 dropped a real
  interface while growing the reply to 202 bytes. Not every array is a time series.
- **Do not grant `gl_screen.*`.** The Flint 4 has a 320x240 LCD and `gl_screen` accepts
  `set`, but `ubus -v list` declares no argument schema and the validation all lives in the
  oui-httpd Lua layer (`check_passcode`, `brightness_min/max`), which `ubus_call` bypasses.
  Called directly, `{"method":"config_update","params":{"config":{"BRIGHTNESS":"40"}}}`
  returns success and writes `BRIGHTNESS '"40"'` — the JSON quotes retained, the type
  corrupted — into both `/tmp/gl_screen/active_config` and UCI, while `gl_screen -l` never
  reflects the change. Other argument shapes are silently ignored. A useful screen tool
  would have to reimplement the Lua layer's validation; the generic path is not safe here.
- **`/tmp/gl_screen/active_config` holds the screen passcode in plaintext** (`PASSCODE
  "1402"`). Any `exec` grant broad enough to read it exposes the device unlock code. The
  auditor's `redact` covers the audit log, not tool output.
- `sms_manager` exists but exposes exactly one ubus method, `set_sms_log_level`. There is no
  send or read surface, and with no modem fitted (`cellular.modem status` → `{"modems": []}`)
  nothing to wrap.

**Known limitations**

- There is **no permanent denylist**. `sysupgrade`, `firstboot` and `mtd` are reachable if a
  policy grants them. That was a deliberate choice; keep recovery access to hand.
- A broadly scoped `exec` grant is a root shell, and from a root shell `openwrt-mcp allow`
  grants anything else. Scoped grants (`exec` limited to named binaries) keep the policy
  engine meaningful; an unscoped one reduces it to an audit trail.
- Rate-limit windows are process-scoped, so a restart resets them — erring toward allowing
  what you already granted.
- Tool output is capped at 64 KB, and ubus replies over 8 KB have arrays capped at 16
  elements. Both cuts say so in the result, but a caller that needs a full time series has
  to reach for a narrower ubus method.
- Install with `make install-ipk`, not `make install`, if you want the daemon to survive a
  firmware upgrade — only the packaged form ships the `keep.d` entry.

---

## Licence

Copyright (C) 2026 Ian Williams. Licensed under the **GNU Affero General Public License
v3.0 or later** — see [LICENSE](LICENSE).

AGPL because this is a network service: if you run a modified version where others can
reach it, §13 requires you to offer them the source. The daemon does this for itself —
`GET /health` returns its version and a link to this repository.
