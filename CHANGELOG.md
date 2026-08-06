# Changelog

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
