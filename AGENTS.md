# Contributing to wg-dbusd

A daemon that publishes WireGuard interface/peer state on the system D-Bus. See
[README.md](README.md) for what it does and the D-Bus interface it exposes.

## Layout

- `src/main.rs` — entry point: logging, connection setup, the poll loop.
- `src/service.rs` — the reconcile loop (add/update/remove D-Bus objects).
- `src/device.rs` / `src/peer.rs` — the `Device`/`Peer` D-Bus interfaces.
- `src/wireguard.rs` — reads WireGuard state from the kernel over netlink.
- `dist/` — the systemd unit and D-Bus policy; `deploy.sh` installs them.

## Build, test, deploy

```sh
cargo build --release
cargo test
./deploy.sh local            # or: ./deploy.sh remote <user>@<host>
```

## Conventions

- **Never put key material on the bus.** The wire types carry the device private
  key and peer preshared key; only base64 *public* keys are ever exposed. Guard
  that when touching `device.rs` / `peer.rs`.
- The **D-Bus interface is the public API** — bus name, object paths, and
  property names are a contract; don't change them casually.
- Keep docstrings and comments minimal.
