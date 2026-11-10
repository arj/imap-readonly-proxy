#!/usr/bin/env bash
# Builds a Debian package: packaging/build-deb.sh <version> <arch>
#   version: X.Y.Z (no leading "v"); arch: amd64 | arm64 | armhf
# Output: dist/imap-readonly-proxy_<version>_<arch>.deb
set -euo pipefail

VERSION="${1:?version}"
ARCH="${2:?arch}"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "invalid version $VERSION" >&2; exit 1; }
case "$ARCH" in
	amd64) GOARCH=amd64 ;;
	arm64) GOARCH=arm64 ;;
	armhf) GOARCH=arm GOARM=7; export GOARM ;;
	*) echo "unsupported arch $ARCH" >&2; exit 1 ;;
esac

cd "$(dirname "$0")/.."
PKG=imap-readonly-proxy
ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT
chmod 0755 "$ROOT"

install -d "$ROOT/DEBIAN" "$ROOT/usr/bin" "$ROOT/lib/systemd/system" \
	"$ROOT/etc/$PKG" "$ROOT/usr/share/doc/$PKG"

CGO_ENABLED=0 GOOS=linux GOARCH=$GOARCH go build -trimpath -buildvcs=false \
	-ldflags "-s -w -X main.version=$VERSION" -o "$ROOT/usr/bin/$PKG" ./cmd/$PKG

install -m 0644 packaging/$PKG.service "$ROOT/lib/systemd/system/$PKG.service"
install -m 0644 config.example.toml README.md SECURITY.md docs/openapi.yaml "$ROOT/usr/share/doc/$PKG/"
install -m 0644 LICENSE "$ROOT/usr/share/doc/$PKG/copyright"
for s in postinst prerm postrm; do
	install -m 0755 packaging/debian/$s "$ROOT/DEBIAN/$s"
done

SIZE=$(du -sk --exclude=DEBIAN "$ROOT" | cut -f1)
cat >"$ROOT/DEBIAN/control" <<CONTROL
Package: $PKG
Version: $VERSION
Architecture: $ARCH
Maintainer: Robert Jakob <330522+arj@users.noreply.github.com>
Installed-Size: $SIZE
Depends: adduser
Section: mail
Priority: optional
Homepage: https://github.com/arj/imap-readonly-proxy
Description: IMAP proxy that grants read-only access to a mailbox
 Parses every client command against an allowlist of read-only IMAP
 commands and re-encodes it for the upstream server, so clients can read
 but never change mail, flags or folders.
CONTROL

mkdir -p dist
OUT="dist/${PKG}_${VERSION}_${ARCH}.deb"
dpkg-deb --root-owner-group --build -Zxz "$ROOT" "$OUT" >/dev/null
echo "$OUT"
