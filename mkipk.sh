#!/bin/sh
# Build an opkg .ipk without the OpenWrt SDK.
#
# The SDK exists to cross-compile C and link against a target toolchain. This binary is
# CGO_ENABLED=0 static Go -- there is nothing to link -- so all that is left is the archive
# format, and an .ipk is just an ar archive of three members in a fixed order:
#
#   debian-binary   the literal "2.0"
#   control.tar.gz  package metadata + maintainer scripts
#   data.tar.gz     the filesystem tree, rooted at ./
#
# Verified against opkg 1bf042dd (2021-06-13) on a GL-BE14000.
#
# Usage: ./mkipk.sh <binary> <version> [ipk-arch]
set -eu

BIN=${1:?usage: mkipk.sh <binary> <version> [arch]}
VERSION=${2:?usage: mkipk.sh <binary> <version> [arch]}
# `opkg print-architecture` on the Flint 2 and Flint 4 both report this.
ARCH=${3:-aarch64_cortex-a53}
PKG=openwrt-mcp
OUT="${PKG}_${VERSION}_${ARCH}.ipk"

SRC=$(cd "$(dirname "$0")" && pwd)
BUILD=$(mktemp -d)
trap 'rm -rf "$BUILD"' EXIT

# ---- data.tar.gz: the files as they land on the router
DATA="$BUILD/data"
mkdir -p "$DATA/usr/bin" "$DATA/etc/init.d" "$DATA/etc/config" "$DATA/lib/upgrade/keep.d" \
         "$DATA/usr/lib/oui-httpd/rpc" "$DATA/usr/share/oui/menu.d"
install -m 0755 "$BIN"                              "$DATA/usr/bin/$PKG"
install -m 0755 "$SRC/files/etc/init.d/$PKG"        "$DATA/etc/init.d/$PKG"
install -m 0644 "$SRC/files/etc/config/$PKG"        "$DATA/etc/config/$PKG"
install -m 0644 "$SRC/files/lib/upgrade/keep.d/$PKG" "$DATA/lib/upgrade/keep.d/$PKG"

# GL.iNet web UI integration. Harmless on stock OpenWrt: without oui-httpd this is an inert
# file nothing reads, so the package stays a single artefact for both.
install -m 0644 "$SRC/files/usr/lib/oui-httpd/rpc/$PKG" "$DATA/usr/lib/oui-httpd/rpc/$PKG"

# The menu entry is only installed once its view bundle exists. A menu.d entry naming a view
# that is not on disk puts a dead item in the router's UI -- the RPC module on its own is
# useful (curl it, or drive it from another client) and invisible, which is the right state
# until there is a page to open.
VIEW="$SRC/files/www/views/gl-sdk4-ui-$PKG.common.js.gz"
if [ -f "$VIEW" ]; then
	mkdir -p "$DATA/www/views"
	install -m 0644 "$VIEW" "$DATA/www/views/gl-sdk4-ui-$PKG.common.js.gz"
	install -m 0644 "$SRC/files/usr/share/oui/menu.d/$PKG.json" "$DATA/usr/share/oui/menu.d/$PKG.json"
else
	echo "note: no view bundle yet, so the menu entry is not packaged" >&2
fi

# ---- control.tar.gz: metadata and maintainer scripts
CTRL="$BUILD/control"
mkdir -p "$CTRL"
cat > "$CTRL/control" <<EOF
Package: $PKG
Version: $VERSION
Depends: libc, ubus, ubox
Source: https://github.com/GlassOnTin/openwrt-mcp
Section: net
Architecture: $ARCH
Maintainer: Ian Williams
Description: MCP server hosted on the router. Exposes ubus, uci and logs to an
 AI agent over loopback, behind bearer auth, standing policies and an audit log.
EOF

# Never overwrite a live policy/token config on upgrade.
echo "/etc/config/$PKG" > "$CTRL/conffiles"

cat > "$CTRL/postinst" <<EOF
#!/bin/sh
[ -n "\${IPKG_INSTROOT:-}" ] && exit 0
/etc/init.d/$PKG enable
/etc/init.d/$PKG restart
exit 0
EOF

cat > "$CTRL/prerm" <<EOF
#!/bin/sh
[ -n "\${IPKG_INSTROOT:-}" ] && exit 0
/etc/init.d/$PKG stop
/etc/init.d/$PKG disable
exit 0
EOF
chmod 0755 "$CTRL/postinst" "$CTRL/prerm"

# ---- assemble. Reproducible: fixed mtime, root ownership, sorted order.
MTIME=${SOURCE_DATE_EPOCH:-0}
TAR="tar --numeric-owner --owner=0 --group=0 --sort=name --mtime=@$MTIME --format=gnu"
# shellcheck disable=SC2086
(cd "$CTRL" && $TAR -czf "$BUILD/control.tar.gz" ./*)
# shellcheck disable=SC2086
(cd "$DATA" && $TAR -czf "$BUILD/data.tar.gz" ./*)
echo "2.0" > "$BUILD/debian-binary"

# The outer container is a gzipped tar, NOT an ar archive.
#
# .ipk has both forms in the wild. The ar form (identical to .deb) is what most
# documentation describes, but the opkg on this target rejects it outright:
#
#   $ opkg install openwrt-mcp.ipk
#   * pkg_init_from_file: Malformed package file /tmp/openwrt-mcp.ipk.
#
# That was with correctly-formed ar headers -- and with binutils' variant, which
# additionally terminates member names with '/'. Both are refused; the gzipped-tar form
# installs. Tested on opkg 1bf042dd (2021-06-13), OpenWrt 21.02-SNAPSHOT, GL-BE14000.
rm -f "$SRC/$OUT"
# shellcheck disable=SC2086
(cd "$BUILD" && $TAR -czf "$SRC/$OUT" ./debian-binary ./control.tar.gz ./data.tar.gz)

echo "$OUT"
