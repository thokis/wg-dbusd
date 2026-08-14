use base64::{Engine as _, engine::general_purpose::STANDARD};
use zbus::interface;
use zbus::object_server::SignalEmitter;

#[derive(Debug)]
pub struct Device {
    device: wireguard_uapi::get::Device,
}

impl From<wireguard_uapi::get::Device> for Device {
    fn from(device: wireguard_uapi::get::Device) -> Self {
        Device { device }
    }
}

impl Device {
    pub async fn update(
        &mut self,
        device: wireguard_uapi::get::Device,
        emitter: &SignalEmitter<'_>,
    ) -> zbus::Result<()> {
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
}
