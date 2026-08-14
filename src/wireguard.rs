//! Reads WireGuard state from the kernel over netlink.

use anyhow::{Context, Result};
use wireguard_uapi::get::Device;
use wireguard_uapi::linux::{DeviceInterface, RouteSocket, WgSocket};

fn get_wireguard_device_names(connection: &mut RouteSocket) -> Result<Vec<String>> {
    RouteSocket::list_device_names(connection).context("listing WireGuard interfaces")
}

/// Read every WireGuard interface; unreadable ones are logged and skipped.
pub fn get_wireguard_devices(
    route_socket: &mut RouteSocket,
    wireguard_socket: &mut WgSocket,
) -> Result<Vec<Device>> {
    let wireguard_device_names = get_wireguard_device_names(route_socket)?;

    let mut wireguard_devices = Vec::new();

    for wireguard_device_name in &wireguard_device_names {
        match WgSocket::get_device(
            wireguard_socket,
            DeviceInterface::from_name(wireguard_device_name),
        ) {
            Ok(wireguard_device) => wireguard_devices.push(wireguard_device),
            Err(e) => log::error!(
                "failed to get WireGuard interface {}: {}",
                wireguard_device_name,
                e
            ),
        }
    }

    Ok(wireguard_devices)
}
