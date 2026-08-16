//! The `Device` D-Bus interface (one object per interface).
//!
use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use zbus::interface;
use zbus::object_server::SignalEmitter;
use zbus::zvariant::OwnedObjectPath;

/// D-Bus wrapper around a WireGuard interface.
#[derive(Debug)]
pub struct Device {
    // SECURITY: never expose the private key — public key only.
    device: wireguard_uapi::get::Device,
    peer_object_paths: Vec<OwnedObjectPath>,
}

impl From<wireguard_uapi::get::Device> for Device {
    fn from(device: wireguard_uapi::get::Device) -> Self {
        Device {
            device,
            peer_object_paths: Vec::new(),
        }
    }
}

impl Device {
    pub fn new(
        device: wireguard_uapi::get::Device,
        peer_object_paths: Vec<OwnedObjectPath>,
    ) -> Self {
        Device {
            device,
            peer_object_paths,
        }
    }
    /// Refresh, emitting `PropertiesChanged` only for changed properties.
    pub async fn update(
        &mut self,
        device: wireguard_uapi::get::Device,
        peer_object_paths: Vec<OwnedObjectPath>,
        emitter: &SignalEmitter<'_>,
    ) -> Result<()> {
        if self.device.public_key != device.public_key {
            self.device.public_key = device.public_key;
            self.public_key_changed(emitter).await?;
        }
        if self.device.listen_port != device.listen_port {
            self.device.listen_port = device.listen_port;
            self.listen_port_changed(emitter).await?;
        }
        if self.device.fwmark != device.fwmark {
            self.device.fwmark = device.fwmark;
            self.fw_mark_changed(emitter).await?;
        }
        if self.peer_object_paths != peer_object_paths {
            self.peer_object_paths = peer_object_paths;
            self.peers_changed(emitter).await?;
        }
        Ok(())
    }
}

#[interface(name = "io.github.thokis.WireGuard1.Device")]
impl Device {
    #[zbus(property(emits_changed_signal = "const"))]
    async fn if_index(&self) -> u32 {
        self.device.ifindex
    }
    #[zbus(property(emits_changed_signal = "const"))]
    async fn if_name(&self) -> &str {
        &self.device.ifname
    }

    #[zbus(property)]
    async fn public_key(&self) -> String {
        match self.device.public_key {
            Some(bytes) => STANDARD.encode(bytes),
            None => "".to_string(),
        }
    }

    #[zbus(property)]
    async fn listen_port(&self) -> u16 {
        self.device.listen_port
    }

    #[zbus(property)]
    async fn fw_mark(&self) -> u32 {
        self.device.fwmark
    }

    #[zbus(property)]
    async fn peers(&self) -> &[OwnedObjectPath] {
        &self.peer_object_paths
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> wireguard_uapi::get::Device {
        wireguard_uapi::get::Device {
            ifindex: 0,
            ifname: "wg0".to_string(),
            private_key: None,
            public_key: None,
            listen_port: 0,
            fwmark: 0,
            peers: vec![],
        }
    }

    #[tokio::test]
    async fn public_key_none_is_empty() {
        assert_eq!(Device::from(sample()).public_key().await, "");
    }

    #[tokio::test]
    async fn public_key_some_is_44_char_base64() {
        let mut wg = sample();
        wg.public_key = Some([0u8; 32]);
        assert_eq!(Device::from(wg).public_key().await.len(), 44);
    }
}
