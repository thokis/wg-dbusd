//! Reconciles the D-Bus object tree with the kernel's WireGuard state.

use crate::device::Device;
use crate::peer::Peer;
use crate::wireguard::get_wireguard_devices;

use anyhow::{Context, Result};
use std::collections::HashSet;
use wireguard_uapi::linux::{RouteSocket, WgSocket};
use zbus::connection;

const BUS_NAME: &str = "io.github.thokis.WireGuard1";
const OBJECT_PATH: &str = "/io/github/thokis/WireGuard1";

/// Owns the bus connection, netlink sockets, and served-path set.
pub struct Service {
    dbus_connection: zbus::Connection,
    desired_object_paths: HashSet<String>,
    served_object_paths: HashSet<String>,
    route_socket: RouteSocket,
    wireguard_socket: WgSocket,
}

impl Service {
    /// Connect to the system bus, claim the name, open the netlink sockets.
    pub async fn new() -> Result<Self> {
        let dbus_connection = connection::Builder::system()
            .context("creating the system-bus connection builder")?
            .name(BUS_NAME)
            .context("setting the bus name")?
            .serve_at(OBJECT_PATH, zbus::fdo::ObjectManager)
            .context("registering the object manager")?
            .build()
            .await
            .context("connecting to the system bus and acquiring the name")?;

        Ok(Service {
            dbus_connection,
            desired_object_paths: HashSet::new(),
            served_object_paths: HashSet::new(),
            route_socket: RouteSocket::connect().context("opening the rtnetlink socket")?,
            wireguard_socket: WgSocket::connect()
                .context("opening the WireGuard netlink socket")?,
        })
    }

    async fn clear_object_paths(&mut self) -> Result<()> {
        let mut stale_object_paths: Vec<_> = self
            .served_object_paths
            .difference(&self.desired_object_paths)
            .cloned()
            .collect();
        stale_object_paths.sort_by_key(|p| std::cmp::Reverse(p.len()));
        for object_path in stale_object_paths {
            if object_path.contains("/Peers/") {
                if let Err(e) = self
                    .dbus_connection
                    .object_server()
                    .remove::<Peer, _>(object_path.as_str().to_string())
                    .await
                {
                    log::error!("could not remove peer object at {}: {}", object_path, e)
                } else {
                    self.served_object_paths.remove(&object_path);
                    log::debug!("peer object {} removed", object_path);
                }
            } else {
                if let Err(e) = self
                    .dbus_connection
                    .object_server()
                    .remove::<Device, _>(object_path.as_str().to_string())
                    .await
                {
                    log::error!("could not remove device object at {}: {}", object_path, e)
                } else {
                    self.served_object_paths.remove(&object_path);
                    log::debug!("device object {} removed", object_path);
                }
            }
        }
        Ok(())
    }

    async fn handle_devices(&mut self) -> Result<()> {
        for mut wg_device in
            get_wireguard_devices(&mut self.route_socket, &mut self.wireguard_socket)?
        {
            let peers = std::mem::take(&mut wg_device.peers);

            let name = wg_device.ifname.clone();
            let object_path = format!("{}/Devices/{}", OBJECT_PATH, name);

            self.desired_object_paths.insert(object_path.clone());

            if !self.served_object_paths.contains(&object_path) {
                if let Err(e) = self
                    .dbus_connection
                    .object_server()
                    .at(object_path.clone(), Device::from(wg_device))
                    .await
                {
                    log::error!("could not serve device {} at {}: {}", name, object_path, e)
                } else {
                    self.served_object_paths.insert(object_path.clone());
                    log::debug!("device object {} added", object_path);
                }
            } else {
                let device_object = self
                    .dbus_connection
                    .object_server()
                    .interface::<_, Device>(object_path)
                    .await?;
                device_object
                    .get_mut()
                    .await
                    .update(wg_device, device_object.signal_emitter())
                    .await?;
            }

            self.handle_peers(&name, peers).await?;
        }
        Ok(())
    }

    async fn handle_peers(
        &mut self,
        device_name: &str,
        peers: Vec<wireguard_uapi::get::Peer>,
    ) -> Result<()> {
        for peer in peers {
            let name = hex::encode(peer.public_key);
            let object_path = format!("{}/Devices/{}/Peers/{}", OBJECT_PATH, device_name, name);

            self.desired_object_paths.insert(object_path.clone());

            if !self.served_object_paths.contains(&object_path) {
                if let Err(e) = self
                    .dbus_connection
                    .object_server()
                    .at(object_path.clone(), Peer::from(peer))
                    .await
                {
                    log::error!("could not serve peer {} at {}: {}", name, object_path, e,)
                } else {
                    self.served_object_paths.insert(object_path.clone());
                    log::debug!("peer object {} added", object_path);
                }
            } else {
                let peer_object = self
                    .dbus_connection
                    .object_server()
                    .interface::<_, Peer>(object_path)
                    .await?;
                peer_object
                    .get_mut()
                    .await
                    .update(peer, peer_object.signal_emitter())
                    .await?;
            }
        }
        Ok(())
    }

    /// One reconcile cycle: converge, then prune.
    pub async fn run(&mut self) -> Result<()> {
        self.desired_object_paths.clear();

        self.handle_devices().await?;

        self.clear_object_paths().await?;

        Ok(())
    }
}
