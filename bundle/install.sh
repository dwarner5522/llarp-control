#!/usr/bin/env bash
# One-shot VPS installer for llarpd + llarpctl.
#
#   sudo ./install.sh [options]
#
# 1. installs build dependencies and builds/installs llarpd from the bundled source
# 2. installs llarpctl (and the GUI if GTK is present)
# 3. generates a config, adds the bundled opennet bootstrap and starts llarpd
#
# Options:
#   --user NAME     account that runs llarpd (default: the sudo caller, else root)
#   --autostart     also start llarpd at boot via systemd (root only)
#   --no-start      install and configure, but don't start llarpd
#   --skip-deps     don't install packages (you already have them)
#   --force-build   rebuild llarpd even if this version is already installed
#   --prefix DIR    where llarpd is installed (default /usr/local)
#   -j N            parallel build jobs (default: based on CPU count and memory)
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
SRC=$HERE/llarp
APP=$HERE/llarp-control
VERSION_TAG=$(cat "$HERE/VERSION")

RUN_USER=${SUDO_USER:-$(id -un)}
AUTOSTART=0
START=1
SKIP_DEPS=0
FORCE_BUILD=0
PREFIX=/usr/local
JOBS=

usage() { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [ $# -gt 0 ]; do
    case $1 in
        --user) RUN_USER=$2; shift ;;
        --autostart) AUTOSTART=1 ;;
        --no-start) START=0 ;;
        --skip-deps) SKIP_DEPS=1 ;;
        --force-build) FORCE_BUILD=1 ;;
        --prefix) PREFIX=$2; shift ;;
        -j) JOBS=$2; shift ;;
        -h|--help) usage ;;
        *) echo "unknown option: $1" >&2; usage 1 ;;
    esac
    shift
done

step() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[33mwarning: %s\033[0m\n' "$*" >&2; }
die() { printf '\033[31merror: %s\033[0m\n' "$*" >&2; exit 1; }

IS_ROOT=0; [ "$(id -u)" = 0 ] && IS_ROOT=1
if [ $IS_ROOT = 0 ]; then
    if [ $SKIP_DEPS = 0 ] || [ ! -w "$PREFIX" ]; then
        die "run as root: sudo $0 $*"
    fi
fi
id "$RUN_USER" >/dev/null 2>&1 || die "no such user: $RUN_USER"
[ "$(uname -s)" = Linux ] || die "llarpd's VPN support needs Linux"

# run a command as the account that will own llarpd
as_user() {
    if [ "$(id -un)" = "$RUN_USER" ]; then
        "$@"
    else
        runuser -u "$RUN_USER" -- env HOME="$(getent passwd "$RUN_USER" | cut -d: -f6)" "$@"
    fi
}

# ---------------------------------------------------------------- 1. dependencies
if [ $SKIP_DEPS = 0 ]; then
    step "Installing build dependencies"
    if command -v apt-get >/dev/null; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -q
        apt-get install -y -q build-essential cmake pkg-config git \
            libuv1-dev libsodium-dev libsystemd-dev libgeoip-dev libssl-dev \
            libcap2-bin iproute2 iptables python3 procps
    elif command -v dnf >/dev/null; then
        dnf install -y gcc-c++ make cmake pkgconf-pkg-config git \
            libuv-devel libsodium-devel systemd-devel GeoIP-devel openssl-devel \
            libcap iproute iptables python3 procps-ng
    elif command -v pacman >/dev/null; then
        pacman -Sy --needed --noconfirm base-devel cmake pkgconf git \
            libuv libsodium systemd-libs geoip openssl libcap iproute2 iptables python procps-ng
    else
        die "unsupported distro (no apt-get, dnf or pacman); install the packages from docs/install.md and rerun with --skip-deps"
    fi
fi

# ---------------------------------------------------------------- 1. build llarpd
LLARPD=$PREFIX/bin/llarpd
if [ $FORCE_BUILD = 0 ] && [ -x "$LLARPD" ] && "$LLARPD" --version 2>/dev/null | grep -q -- "$VERSION_TAG"; then
    step "llarpd $VERSION_TAG is already installed at $LLARPD; skipping build (--force-build to rebuild)"
else
    if [ -z "$JOBS" ]; then
        # each compiler process can use ~1.5 GB; small VPSes run out of memory otherwise
        mem_kb=$(awk '/MemAvailable/ {print $2}' /proc/meminfo)
        by_mem=$(( mem_kb / 1500000 )); [ $by_mem -lt 1 ] && by_mem=1
        JOBS=$(nproc); [ $by_mem -lt $JOBS ] && JOBS=$by_mem
    fi
    LTO=ON
    total_kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
    if [ "$total_kb" -lt 2500000 ]; then
        LTO=OFF
        warn "less than 2.5 GB RAM: building without link-time optimisation; add swap if the build gets killed"
    fi

    step "Building llarpd $VERSION_TAG with $JOBS job(s) (this takes a while)"
    BUILD=$HERE/build
    cmake -S "$SRC" -B "$BUILD" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX="$PREFIX" \
        -DBUILD_SHARED_LIBS=OFF \
        -DWITH_TESTS=OFF \
        -DWITH_LTO=$LTO \
        -DLLARP_VERSIONTAG="$VERSION_TAG"
    cmake --build "$BUILD" -j "$JOBS"

    step "Installing llarpd to $PREFIX/bin"
    if [ -n "$(pgrep -x llarpd || true)" ]; then
        warn "llarpd is running; it keeps using the old binary until restarted (llarpctl restart)"
    fi
    cmake --install "$BUILD"
fi

# make sure the binary may create the tunnel without running as root
if [ $IS_ROOT = 1 ] && command -v setcap >/dev/null; then
    setcap cap_net_admin,cap_net_bind_service=+eip "$LLARPD"
fi
"$LLARPD" --version

# ---------------------------------------------------------------- 2. llarpctl
step "Installing llarpctl"
"$APP/install.sh"
if [ $IS_ROOT = 1 ]; then
    LLARPCTL=/usr/local/bin/llarpctl
else
    LLARPCTL=$HOME/.local/bin/llarpctl
fi

# ---------------------------------------------------------------- 3. configure & start
step "Configuring llarpd for user '$RUN_USER'"
as_user "$LLARPCTL" set llarpd "$LLARPD" >/dev/null
CONFIG=$(as_user "$LLARPCTL" set config)
if [ -f "$CONFIG" ]; then
    echo "using existing config $CONFIG"
else
    as_user mkdir -p "$(dirname "$CONFIG")"
    as_user "$LLARPCTL" generate-config | tail -1
fi
if [[ $(as_user "$LLARPCTL" bootstrap list) == *opennet.signed* ]]; then
    echo "opennet bootstrap already added"
else
    as_user "$LLARPCTL" bootstrap add opennet
fi

if [ $AUTOSTART = 1 ]; then
    if [ "$RUN_USER" = root ] && [ $IS_ROOT = 1 ]; then
        as_user "$LLARPCTL" autostart on
    else
        warn "--autostart is only set up automatically when llarpd runs as root (use --user root); skipping"
    fi
fi

if [ $START = 1 ]; then
    if [[ $(as_user "$LLARPCTL" status --json) == *'"running": true'* ]]; then
        step "llarpd is already running; restarting to apply changes"
        as_user "$LLARPCTL" restart --wait 60
    elif [ $AUTOSTART = 1 ] && [ "$RUN_USER" = root ] && [ $IS_ROOT = 1 ]; then
        step "Starting llarpd via systemd"
        systemctl start llarp-control
        sleep 3
    else
        step "Starting llarpd"
        as_user "$LLARPCTL" start --wait 60
    fi
fi

step "Done"
as_user "$LLARPCTL" status || true
cat <<EOF

Control it with llarpctl${RUN_USER:+ (as $RUN_USER)}:
  llarpctl status | start | stop | restart | log -f
  llarpctl exit on && llarpctl fwd enable     # become an exit node
  llarpctl --help
EOF
