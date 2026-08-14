#!/bin/sh
# Build and deploy wg-dbusd as a system service, locally or on a remote host.
#
# Run as your NORMAL user (NOT sudo): it builds for the target host's arch, then
# runs only the privileged install steps via sudo.
#     ./deploy.sh local                    # this machine, glibc
#     ./deploy.sh remote <user>@<host>     # a remote host, glibc
#     ./deploy.sh musl local               # static musl build instead
#     ./deploy.sh musl remote <user>@<host>
#
# The optional first arg is the C library (glibc, the default, or musl); the arch
# is detected from the (remote) host, so a Pi never gets an x86_64 binary. Local
# prompts for your sudo password; remote assumes NOPASSWD sudo (normal on a Pi).
# musl and cross-arch builds go through `cross` (cargo install cross + docker/podman).
set -eu
cd "$(dirname "$0")"

BIN_DEST=/usr/local/sbin/wg-dbusd
POLICY_DEST=/usr/share/dbus-1/system.d/io.github.thokis.WireGuard1.conf
UNIT_DEST=/etc/systemd/system/wg-dbusd.service
SVC_USER=wg-dbusd
POLICY_SRC=dist/io.github.thokis.WireGuard1.conf
UNIT_SRC=dist/wg-dbusd.service

usage() {
    cat >&2 <<'USAGE'
usage:
  ./deploy.sh [glibc|musl] local                  build + install on this machine
  ./deploy.sh [glibc|musl] remote <user>@<host>   build + install on a remote host

The optional first arg picks the C library (default glibc); the architecture is
detected from the target host. musl yields a static binary for older systems.
USAGE
    exit 1
}

# Map a machine arch ($1, as `uname -m`) and libc ($2, glibc|musl) to a Rust triple.
triple_for() {
    case "$1" in
        x86_64|amd64)       arch=x86_64;  suffix= ;;
        aarch64|arm64)      arch=aarch64; suffix= ;;
        armv7l|armv7|armhf) arch=armv7;   suffix=eabihf ;;
        *) echo "unsupported arch: $1" >&2; return 1 ;;
    esac
    case "$2" in
        glibc) abi=gnu ;;
        musl)  abi=musl ;;
        *) echo "unsupported libc: $2 (use glibc or musl)" >&2; return 1 ;;
    esac
    echo "${arch}-unknown-linux-${abi}${suffix}"
}

# The host's own triple, which `cargo` builds without cross-compiling.
host_triple() { triple_for "$(uname -m)" glibc; }

# Build the release binary for target triple $1: native `cargo` (with tests) for
# the host's own triple, else `cross`.
build() {
    target="$1"
    if [ "$target" = "$(host_triple)" ]; then
        cargo test
        cargo build --release
    else
        cross build --release --target "$target"
    fi
}

# Print the built binary for target triple $1, or fail. The host's own triple
# lands in target/release; a cross target in target/<triple>/release.
binary_for_target() {
    target="$1"
    if [ "$target" = "$(host_triple)" ] && [ -x target/release/wg-dbusd ]; then
        echo target/release/wg-dbusd
        return 0
    fi
    if [ -x "target/$target/release/wg-dbusd" ]; then
        echo "target/$target/release/wg-dbusd"
        return 0
    fi
    return 1
}

# Emit the privileged install steps for source paths: $1 binary, $2 policy, $3 unit.
install_steps() {
    cat <<STEPS
id "$SVC_USER" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$SVC_USER"
install -m 0755 "$1" "$BIN_DEST"
install -m 0644 "$2" "$POLICY_DEST"
install -m 0644 "$3" "$UNIT_DEST"
systemctl reload dbus
systemctl daemon-reload
systemctl enable wg-dbusd
systemctl restart wg-dbusd
STEPS
}

do_local() {
    target="$(triple_for "$(uname -m)" "${1:-glibc}")" || exit 1
    build "$target"
    bin="$(binary_for_target "$target")" || { echo "build produced no binary for $target" >&2; exit 1; }

    echo "installing locally (sudo)..."
    install_steps "$bin" "$POLICY_SRC" "$UNIT_SRC" | sudo sh -eu
    echo "installed. follow logs: journalctl -u wg-dbusd -f"
}

do_remote() {
    libc="${1:-glibc}"
    addr="$2"
    case "$addr" in
        ?*@?*) : ;;
        *) echo "remote needs <user>@<host>, e.g. ./deploy.sh remote pi@raspberrypi" >&2; exit 1 ;;
    esac

    arch="$(ssh "$addr" uname -m)" || { echo "cannot reach $addr over ssh" >&2; exit 1; }
    target="$(triple_for "$arch" "$libc")" || exit 1
    build "$target"
    bin="$(binary_for_target "$target")" || { echo "build produced no binary for $target" >&2; exit 1; }

    stage="/tmp/wg-dbusd-install.$$"
    ssh "$addr" "mkdir -p '$stage'"
    scp "$bin" "$addr:$stage/wg-dbusd"
    scp "$POLICY_SRC" "$addr:$stage/policy.conf"
    scp "$UNIT_SRC" "$addr:$stage/wg-dbusd.service"

    echo "installing on $addr (sudo)..."
    { install_steps "$stage/wg-dbusd" "$stage/policy.conf" "$stage/wg-dbusd.service"; printf 'rm -rf %s\n' "$stage"; } \
        | ssh "$addr" "sudo sh -eu"
    echo "installed on $addr ($target). logs: ssh $addr journalctl -u wg-dbusd -f"
}

# An optional libc flavor (glibc|musl) may precede the local/remote verb.
libc=""
case "${1:-}" in
    local|remote) : ;;
    glibc|musl)   libc="$1"; shift ;;
    *)            usage ;;
esac

case "${1:-}" in
    local)  do_local "$libc" ;;
    remote) do_remote "$libc" "${2:-}" ;;
    *)      usage ;;
esac
