#!/bin/sh
# Build an APK package without the OpenWrt SDK.
#
# The binary is CGO_ENABLED=0 static Go, so there is nothing to link against. An APK is a
# gzip-compressed tar archive containing .PKGINFO, optional install scripts, and files rooted
# at /.
#
# Usage: ./mkapk.sh <binary> <version> [apk-arch]
set -eu

BIN=${1:?usage: mkapk.sh <binary> <version> [arch]}
VERSION=${2:?usage: mkapk.sh <binary> <version> [arch]}
ARCH=${3:-aarch64_cortex-a53}
PKG=openwrt-mcp
OUT="${PKG}-${VERSION}.apk"

SRC=$(cd "$(dirname "$0")" && pwd)
BUILD=$(mktemp -d)
trap 'rm -rf "$BUILD"' EXIT

# The payload as it lands on the router.
DATA="$BUILD/data"
mkdir -p "$DATA/usr/bin" "$DATA/etc/init.d" "$DATA/etc/config" "$DATA/lib/upgrade/keep.d" \
		 "$DATA/usr/lib/oui-httpd/rpc" "$DATA/usr/libexec/rpcd" \
		 "$DATA/usr/share/oui/menu.d" "$DATA/usr/share/rpcd/acl.d" \
		 "$DATA/usr/share/luci/menu.d" "$DATA/www/luci-static/resources/view/openwrt-mcp"
install -m 0755 "$BIN" "$DATA/usr/bin/$PKG"
install -m 0755 "$SRC/files/etc/init.d/$PKG" "$DATA/etc/init.d/$PKG"
install -m 0644 "$SRC/files/etc/config/$PKG" "$DATA/etc/config/$PKG"
install -m 0644 "$SRC/files/lib/upgrade/keep.d/$PKG" "$DATA/lib/upgrade/keep.d/$PKG"
install -m 0644 "$SRC/files/usr/lib/oui-httpd/rpc/$PKG" "$DATA/usr/lib/oui-httpd/rpc/$PKG"
install -m 0755 "$SRC/files/usr/libexec/rpcd/luci.openwrt_mcp" "$DATA/usr/libexec/rpcd/luci.openwrt_mcp"
install -m 0644 "$SRC/files/usr/share/rpcd/acl.d/luci-app-$PKG.json" \
	"$DATA/usr/share/rpcd/acl.d/luci-app-$PKG.json"
install -m 0644 "$SRC/files/usr/share/luci/menu.d/luci-app-$PKG.json" \
	"$DATA/usr/share/luci/menu.d/luci-app-$PKG.json"
install -m 0644 "$SRC/files/www/luci-static/resources/view/$PKG/status.js" \
	"$DATA/www/luci-static/resources/view/$PKG/status.js"

VIEW_SRC="$SRC/ui/view.js"
if [ -f "$VIEW_SRC" ]; then
	mkdir -p "$DATA/www/views" "$DATA/www/i18n"
	gzip -9 -c "$VIEW_SRC" > "$DATA/www/views/gl-sdk4-ui-$PKG.common.js.gz"
	chmod 0644 "$DATA/www/views/gl-sdk4-ui-$PKG.common.js.gz"
	install -m 0644 "$SRC/files/usr/share/oui/menu.d/$PKG.json" "$DATA/usr/share/oui/menu.d/$PKG.json"
	for lang in "$SRC/files/www/i18n/gl-sdk4-ui-$PKG."*.json; do
		[ -f "$lang" ] && install -m 0644 "$lang" "$DATA/www/i18n/$(basename "$lang")"
	done
else
	echo "note: no ui/view.js, so the view and its menu entry are not packaged" >&2
fi

# APK 3 metadata and lifecycle scripts. APK protects /etc by default, which preserves the
# live policy and token configuration when the package is upgraded.
cat > "$BUILD/post-install" <<EOF
#!/bin/sh
[ -n "\${IPKG_INSTROOT:-}\${APK_INSTROOT:-}" ] && exit 0
/etc/init.d/$PKG enable
/etc/init.d/$PKG stop >/dev/null 2>&1 || true
/etc/init.d/$PKG start
exit 0
EOF

cat > "$BUILD/pre-deinstall" <<EOF
#!/bin/sh
[ -n "\${IPKG_INSTROOT:-}\${APK_INSTROOT:-}" ] && exit 0
/etc/init.d/$PKG stop
/etc/init.d/$PKG disable
exit 0
EOF
chmod 0755 "$BUILD/post-install" "$BUILD/pre-deinstall"

APK_TOOL=${APK_TOOL:-}
if [ -z "$APK_TOOL" ]; then
	APK_TOOL=$(command -v apk || true)
fi
if [ -z "$APK_TOOL" ]; then
	APK_CACHE=${APK_CACHE:-${TMPDIR:-/tmp}/openwrt-mcp-apk-tools-static}
	APK_TOOL="$APK_CACHE/sbin/apk.static"
	if [ ! -x "$APK_TOOL" ]; then
		command -v curl >/dev/null 2>&1 || {
			echo "error: apk-tools 3 is required (install apk, set APK_TOOL, or install curl)" >&2
			exit 1
		}
		APK_INDEX=$(curl -fsSL https://dl-cdn.alpinelinux.org/alpine/edge/main/x86_64/)
		APK_PACKAGE=$(printf '%s\n' "$APK_INDEX" | sed -n 's/.*href="\(apk-tools-static-[^"]*\.apk\)".*/\1/p' | tail -1)
		[ -n "$APK_PACKAGE" ] || {
			echo "error: could not locate an APK 3 static tool" >&2
			exit 1
		}
		APK_DOWNLOAD=$(mktemp -d)
		trap 'rm -rf "$BUILD" "$APK_DOWNLOAD"' EXIT
		mkdir -p "$APK_CACHE"
		curl -fsSL -o "$APK_DOWNLOAD/apk-tools-static.apk" \
			"https://dl-cdn.alpinelinux.org/alpine/edge/main/x86_64/$APK_PACKAGE"
		tar -xzf "$APK_DOWNLOAD/apk-tools-static.apk" -C "$APK_CACHE"
	fi
fi
command -v "$APK_TOOL" >/dev/null 2>&1 || [ -x "$APK_TOOL" ] || {
	echo "error: APK_TOOL does not point to an executable apk-tools 3 binary" >&2
	exit 1
}
rm -f "$SRC/$OUT"
"$APK_TOOL" mkpkg \
	-I "name:$PKG" \
	-I "version:$VERSION" \
	-I "arch:$ARCH" \
	-I "origin:$PKG" \
	-I "maintainer:Ian Williams" \
	-I "license:MIT" \
	-I "url:https://github.com/GlassOnTin/openwrt-mcp" \
	-I "description:MCP server hosted on the router. Exposes ubus, uci and logs to an AI agent over loopback, behind bearer auth, standing policies and an audit log." \
	-I "depends:libc ubus ubox rpcd luci-base" \
	-F "$DATA" \
	-s "post-install:$BUILD/post-install" \
	-s "pre-deinstall:$BUILD/pre-deinstall" \
	-o "$SRC/$OUT"

echo "$OUT"