#!/bin/sh
# FuckAds installer for macOS 11+ (Intel and Apple Silicon).
#
#   curl -fsSL https://raw.githubusercontent.com/PankajKrana/fuck-ads/main/installers/install-macos.sh | sh
#   ./installers/install-macos.sh           # from a source checkout (builds with cargo)
#
# Environment:
#   FUCK_ADS_REPO=owner/repo       GitHub repository for release downloads
#   FUCK_ADS_VERSION=0.1.0         release to install (default: latest)
#   FUCK_ADS_FROM_SOURCE=1         force building from source
#   FUCK_ADS_NO_ENABLE=1           install but do not turn protection on
set -eu

REPO="${FUCK_ADS_REPO:-PankajKrana/fuck-ads}"
VERSION="${FUCK_ADS_VERSION:-latest}"
PREFIX="${FUCK_ADS_PREFIX:-/usr/local}"
BIN_DIR="$PREFIX/bin"
SHARE_DIR="$PREFIX/share/fuck-ads"
BASE_DIR="/Library/Application Support/FuckAds"
LOG_DIR=/Library/Logs/FuckAds
PLIST=/Library/LaunchDaemons/com.fuckads.daemon.plist
SYNC_PLIST=/Library/LaunchDaemons/com.fuckads.sync.plist
SERVICE_USER=_fuck-ads

say()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }

# --- 1. Detect OS and architecture -----------------------------------------
[ "$(uname -s)" = "Darwin" ] || die "this installer is for macOS; on Linux use install.sh"
case "$(uname -m)" in
    x86_64) TARGET=x86_64-apple-darwin ;;
    arm64)  TARGET=aarch64-apple-darwin ;;
    *) die "unsupported architecture: $(uname -m)" ;;
esac
OS_MAJOR="$(sw_vers -productVersion | cut -d. -f1)"
[ "$OS_MAJOR" -ge 11 ] || die "macOS 11 (Big Sur) or later is required"
say "Detected macOS $(sw_vers -productVersion) on $(uname -m)"

# --- 2. Privileges -------------------------------------------------------------
if [ "$(id -u)" -eq 0 ]; then SUDO=""; else need sudo; SUDO="sudo"; fi

# --- 3. Dependencies -----------------------------------------------------------
need launchctl
need networksetup
need dscl
need shasum

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT INT TERM

# --- 4. Obtain the binary and data files --------------------------------------
SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" 2>/dev/null && pwd || echo "")"
SRC_ROOT=""
if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/../Cargo.toml" ] && [ -d "$SCRIPT_DIR/../crates/fuck-ads-cli" ]; then
    SRC_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
fi

if [ -n "$SRC_ROOT" ] || [ "${FUCK_ADS_FROM_SOURCE:-0}" = "1" ]; then
    [ -n "$SRC_ROOT" ] || die "FUCK_ADS_FROM_SOURCE=1 requires running from a source checkout"
    if ! command -v cargo >/dev/null 2>&1 && [ -x "$HOME/.cargo/bin/cargo" ]; then
        PATH="$HOME/.cargo/bin:$PATH"
    fi
    command -v cargo >/dev/null 2>&1 || die "cargo not found; install Rust from https://rustup.rs or use a release build"
    xcode-select -p >/dev/null 2>&1 || die "Xcode Command Line Tools are required: xcode-select --install"
    say "Building from source in $SRC_ROOT (this takes a few minutes the first time)"
    (cd "$SRC_ROOT" && cargo build --release --locked -p fuck-ads-cli) || die "build failed"
    mkdir -p "$WORK/pkg/share/filters" "$WORK/pkg/platforms"
    cp "$SRC_ROOT/target/release/fuck-ads" "$WORK/pkg/fuck-ads"
    cp "$SRC_ROOT"/filters/*.txt "$WORK/pkg/share/filters/"
    cp "$SRC_ROOT/platforms/macos/com.fuckads.daemon.plist" "$SRC_ROOT/platforms/macos/com.fuckads.sync.plist" \
       "$SRC_ROOT/platforms/macos/newsyslog-fuck-ads.conf" "$WORK/pkg/platforms/"
    if [ -x "$SRC_ROOT/browser/build.sh" ]; then
        "$SRC_ROOT/browser/build.sh" >/dev/null && cp -R "$SRC_ROOT/browser/dist" "$WORK/pkg/share/browser"
    fi
else
    need curl
    if [ "$VERSION" = "latest" ]; then
        BASE="https://github.com/$REPO/releases/latest/download"
    else
        BASE="https://github.com/$REPO/releases/download/v$VERSION"
    fi
    ARCHIVE="fuck-ads-$TARGET.tar.gz"
    say "Downloading $ARCHIVE"
    curl -fsSL --proto '=https' --tlsv1.2 -o "$WORK/$ARCHIVE" "$BASE/$ARCHIVE" || die "download failed: $BASE/$ARCHIVE"
    curl -fsSL --proto '=https' --tlsv1.2 -o "$WORK/$ARCHIVE.sha256" "$BASE/$ARCHIVE.sha256" || die "checksum download failed"
    say "Verifying checksum"
    EXPECTED="$(cut -d' ' -f1 < "$WORK/$ARCHIVE.sha256")"
    ACTUAL="$(shasum -a 256 "$WORK/$ARCHIVE" | cut -d' ' -f1)"
    [ "$EXPECTED" = "$ACTUAL" ] || die "checksum mismatch for $ARCHIVE"
    mkdir -p "$WORK/pkg"
    tar -xzf "$WORK/$ARCHIVE" -C "$WORK/pkg"
    [ -f "$WORK/pkg/fuck-ads" ] || die "archive does not contain the fuck-ads binary"
    # Downloaded via curl, so no quarantine attribute is set; clear it anyway.
    xattr -d com.apple.quarantine "$WORK/pkg/fuck-ads" 2>/dev/null || true
fi

"$WORK/pkg/fuck-ads" --version >/dev/null || die "the binary does not run on this Mac"

# --- 5. Service account ----------------------------------------------------------
if ! dscl . -read "/Users/$SERVICE_USER" >/dev/null 2>&1; then
    say "Creating service account '$SERVICE_USER'"
    # First free ID in the system range 400-499 used by both user and group.
    ID=""
    for candidate in $(seq 400 499); do
        if ! dscl . -list /Users UniqueID | awk '{print $2}' | grep -qx "$candidate" &&
           ! dscl . -list /Groups PrimaryGroupID | awk '{print $2}' | grep -qx "$candidate"; then
            ID="$candidate"; break
        fi
    done
    [ -n "$ID" ] || die "no free system user ID in 400-499"
    $SUDO dscl . -create "/Groups/$SERVICE_USER"
    $SUDO dscl . -create "/Groups/$SERVICE_USER" PrimaryGroupID "$ID"
    $SUDO dscl . -create "/Groups/$SERVICE_USER" RealName "FuckAds"
    $SUDO dscl . -create "/Groups/$SERVICE_USER" Password '*'
    $SUDO dscl . -create "/Users/$SERVICE_USER"
    $SUDO dscl . -create "/Users/$SERVICE_USER" UniqueID "$ID"
    $SUDO dscl . -create "/Users/$SERVICE_USER" PrimaryGroupID "$ID"
    $SUDO dscl . -create "/Users/$SERVICE_USER" UserShell /usr/bin/false
    $SUDO dscl . -create "/Users/$SERVICE_USER" NFSHomeDirectory /var/empty
    $SUDO dscl . -create "/Users/$SERVICE_USER" RealName "FuckAds"
    $SUDO dscl . -create "/Users/$SERVICE_USER" Password '*'
    $SUDO dscl . -create "/Users/$SERVICE_USER" IsHidden 1
fi

# --- 6. Install files ------------------------------------------------------------
say "Installing to $PREFIX"
UPGRADE=0
if [ -x "$BIN_DIR/fuck-ads" ] && launchctl print system/com.fuckads.daemon >/dev/null 2>&1; then UPGRADE=1; fi

$SUDO install -d -m 0755 "$BIN_DIR" "$SHARE_DIR" "$SHARE_DIR/filters"
$SUDO install -m 0755 "$WORK/pkg/fuck-ads" "$BIN_DIR/fuck-ads.new"
$SUDO mv -f "$BIN_DIR/fuck-ads.new" "$BIN_DIR/fuck-ads"
$SUDO ln -sf "$BIN_DIR/fuck-ads" "$BIN_DIR/fuck-ads-native-host"
$SUDO install -m 0644 "$WORK"/pkg/share/filters/*.txt "$SHARE_DIR/filters/"
if [ -d "$WORK/pkg/share/browser" ]; then
    $SUDO rm -rf "$SHARE_DIR/browser"
    $SUDO cp -R "$WORK/pkg/share/browser" "$SHARE_DIR/browser"
    $SUDO chmod -R a+rX "$SHARE_DIR/browser"
fi

$SUDO install -d -m 0755 "$BASE_DIR"
$SUDO install -d -m 0755 -o "$SERVICE_USER" -g "$SERVICE_USER" "$BASE_DIR/data" "$LOG_DIR"
if [ ! -f "$BASE_DIR/config.toml" ]; then
    "$WORK/pkg/fuck-ads" config default > "$WORK/config.toml"
    $SUDO install -m 0644 "$WORK/config.toml" "$BASE_DIR/config.toml"
    say "Wrote default configuration to $BASE_DIR/config.toml"
else
    say "Keeping existing configuration"
fi
$SUDO install -m 0644 "$WORK/pkg/platforms/newsyslog-fuck-ads.conf" /etc/newsyslog.d/fuck-ads.conf

sed "s#/usr/local/bin/fuck-ads#$BIN_DIR/fuck-ads#g" "$WORK/pkg/platforms/com.fuckads.daemon.plist" > "$WORK/daemon.plist"
plutil -lint "$WORK/daemon.plist" >/dev/null || die "invalid LaunchDaemon plist"
$SUDO install -m 0644 -o root -g wheel "$WORK/daemon.plist" "$PLIST"
sed "s#/usr/local/bin/fuck-ads#$BIN_DIR/fuck-ads#g" "$WORK/pkg/platforms/com.fuckads.sync.plist" > "$WORK/sync.plist"
plutil -lint "$WORK/sync.plist" >/dev/null || die "invalid LaunchDaemon plist"
$SUDO install -m 0644 -o root -g wheel "$WORK/sync.plist" "$SYNC_PLIST"

$SUDO "$BIN_DIR/fuck-ads" browser install --system >/dev/null || warn "could not register browser integration"

# --- 7. Validate -------------------------------------------------------------------
"$BIN_DIR/fuck-ads" config validate >/dev/null || die "configuration is invalid: run 'fuck-ads config validate'"

# --- 8. Start ----------------------------------------------------------------------
if [ "$UPGRADE" = "1" ]; then
    say "Restarting the upgraded service"
    # Reload the plist in case it changed, then restart.
    $SUDO launchctl bootout system/com.fuckads.daemon 2>/dev/null || true
    $SUDO launchctl bootout system/com.fuckads.sync 2>/dev/null || true
    $SUDO "$BIN_DIR/fuck-ads" start
elif [ "${FUCK_ADS_NO_ENABLE:-0}" != "1" ]; then
    say "Enabling protection"
    $SUDO "$BIN_DIR/fuck-ads" enable || die "enable failed; your previous DNS settings are unchanged. See 'fuck-ads doctor'."
fi

# --- 9. Initial filter lists and health check ---------------------------------------
if launchctl print system/com.fuckads.daemon >/dev/null 2>&1; then
    say "Downloading filter lists"
    $SUDO "$BIN_DIR/fuck-ads" update || warn "filter download failed; bundled rules are active and updates will retry automatically"
    echo
    "$BIN_DIR/fuck-ads" doctor || true
fi

cat <<EOF

FuckAds is installed.

  fuck-ads status          show status
  sudo fuck-ads disable    turn protection off
  fuck-ads doctor          diagnose problems

Browser extension (recommended, needed for in-page and YouTube ads):
  $SHARE_DIR/browser/chromium   (chrome://extensions → Developer mode → Load unpacked)
  $SHARE_DIR/browser/firefox    (about:debugging → Load Temporary Add-on)
  Safari: see https://github.com/$REPO/blob/main/browser/safari/README.md
EOF
