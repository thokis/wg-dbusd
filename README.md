# wg-dbusd

[![CI](https://github.com/thokis/wg-dbusd/actions/workflows/ci.yml/badge.svg)](https://github.com/thokis/wg-dbusd/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/thokis/wg-dbusd)](https://github.com/thokis/wg-dbusd/releases/latest)

A small daemon that publishes each **WireGuard** interface and peer as an object
on the **system D-Bus**, and keeps that view in sync with the kernel. It reads
WireGuard state over netlink (which needs `CAP_NET_ADMIN`) and exposes a
read-only, policy-gated view on the bus, so unprivileged clients — a status
applet, a monitor, a supervisor — can watch tunnel health without touching
netlink themselves.

## Features

- One D-Bus object per interface and per peer, under an `ObjectManager`.
- Live: interfaces and peers appear/disappear and their properties update as the
  kernel changes, with `PropertiesChanged` signals (handshake, endpoint, …).
- **Never exposes key material** — only base64 *public* keys; device private
  keys and peer preshared keys are read but never surfaced on the bus.
- Ships a hardened `systemd` unit (dedicated user, `AmbientCapabilities=CAP_NET_ADMIN`)
  and a D-Bus policy.

## The D-Bus interface

Bus name **`io.github.thokis.WireGuard1`** on the **system** bus.

```
/io/github/thokis/WireGuard1                                  org.freedesktop.DBus.ObjectManager
/io/github/thokis/WireGuard1/Devices/<ifname>                 io.github.thokis.WireGuard1.Device
/io/github/thokis/WireGuard1/Devices/<ifname>/Peers/<hexkey>  io.github.thokis.WireGuard1.Peer
```

Peer object paths are keyed by the **hex** of the 32-byte public key (base64 is
not legal in a D-Bus path).

**`…Device`**

| Property     | Type | Notes                          |
|--------------|------|--------------------------------|
| `IfIndex`    | `u`  | constant                       |
| `IfName`     | `s`  | constant                       |
| `PublicKey`  | `s`  | base64, `""` if unset          |
| `ListenPort` | `q`  |                                |
| `FwMark`     | `u`  |                                |

**`…Peer`**

| Property                      | Type | Notes                               |
|-------------------------------|------|-------------------------------------|
| `PublicKey`                   | `s`  | base64                              |
| `Endpoint`                    | `s`  | `ip:port`, `""` if none             |
| `PersistentKeepaliveInterval` | `q`  | seconds, `0` = off                  |
| `LastHandshakeTime`           | `t`  | **Unix epoch seconds, `0` = never** |
| `RxBytes` / `TxBytes`         | `t`  | no change signal (poll them)        |
| `AllowedIps`                  | `as` | `ip/cidr` strings                   |
| `ProtocolVersion`             | `u`  |                                     |

The machine-readable introspection XML lives in [`dist/interfaces/`](dist/interfaces/) —
run `zbus-xmlgen` on it to generate a typed client proxy.

## Install

```sh
./deploy.sh local
./deploy.sh remote <user>@<host>      # assumes NOPASSWD sudo on the remote host
./deploy.sh musl remote <user>@<host> # static musl build
```

`deploy.sh` detects the target host's architecture and builds for it,
then installs the binary, D-Bus policy and systemd unit and enables the service.

An optional first argument picks the C library — `glibc` (default) or `musl`.

Prebuilt binaries for tagged releases are on the
[releases page](https://github.com/thokis/wg-dbusd/releases).

## Usage

```sh
busctl --system tree io.github.thokis.WireGuard1
busctl --system call io.github.thokis.WireGuard1 /io/github/thokis/WireGuard1 \
    org.freedesktop.DBus.ObjectManager GetManagedObjects
busctl --system get-property io.github.thokis.WireGuard1 \
    /io/github/thokis/WireGuard1/Devices/wg0/Peers/<hex> \
    io.github.thokis.WireGuard1.Peer LastHandshakeTime
busctl --system monitor io.github.thokis.WireGuard1   # watch churn + property changes live
```

## Security

Read-only. The daemon holds `CAP_NET_ADMIN` (to read WireGuard over netlink) but
runs as a dedicated non-root user with a restrictive systemd sandbox. It never
places private or preshared keys on the bus. The bundled policy lets any local
client *read*.

## License

BSD-3-Clause. See [LICENSE](LICENSE).
