#!/bin/sh
# Builds the release archive consumed by the installers and packages:
#
#   packaging/make-dist.sh <rust-target> <path-to-fuck-ads-binary> [outdir]
#
# Layout:  fuck-ads, share/filters/*.txt, share/browser/{chromium,firefox},
#          platforms/*, LICENSE, README.md
set -eu
TARGET="$1"; BIN="$2"; OUT="${3:-dist}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/share/filters" "$STAGE/platforms" "$OUT"
install -m 0755 "$BIN" "$STAGE/fuck-ads"
cp "$ROOT"/filters/*.txt "$STAGE/share/filters/"
cp "$ROOT/platforms/linux/fuck-ads.service" "$ROOT/platforms/macos/com.fuckads.daemon.plist" \
   "$ROOT/platforms/macos/com.fuckads.sync.plist" \
   "$ROOT/platforms/macos/newsyslog-fuck-ads.conf" "$STAGE/platforms/"
"$ROOT/browser/build.sh" >/dev/null
mkdir -p "$STAGE/share/browser"
cp -R "$ROOT/browser/dist/chromium" "$ROOT/browser/dist/firefox" "$STAGE/share/browser/"
cp "$ROOT/LICENSE" "$ROOT/README.md" "$STAGE/"
ARCHIVE="$OUT/fuck-ads-$TARGET.tar.gz"
tar -czf "$ARCHIVE" -C "$STAGE" .
if command -v sha256sum >/dev/null 2>&1; then
    (cd "$OUT" && sha256sum "fuck-ads-$TARGET.tar.gz" > "fuck-ads-$TARGET.tar.gz.sha256")
else
    (cd "$OUT" && shasum -a 256 "fuck-ads-$TARGET.tar.gz" > "fuck-ads-$TARGET.tar.gz.sha256")
fi
echo "$ARCHIVE"
