use base64::{Engine as _, engine::general_purpose::STANDARD};
use zbus::interface;
use zbus::object_server::SignalEmitter;

#[derive(Debug)]
pub struct Peer {
    peer: wireguard_uapi::get::Peer,
}

impl From<wireguard_uapi::get::Peer> for Peer {
    fn from(peer: wireguard_uapi::get::Peer) -> Self {
        Peer { peer }
    }
}

impl Peer {
    pub async fn update(
        &mut self,
        peer: wireguard_uapi::get::Peer,
        emitter: &SignalEmitter<'_>,
    ) -> zbus::Result<()> {
        if self.peer.public_key != peer.public_key {
            self.peer.public_key = peer.public_key;
            self.public_key_changed(emitter).await?;
        }
        if self.peer.endpoint != peer.endpoint {
            self.peer.endpoint = peer.endpoint;
            self.endpoint_changed(emitter).await?;
        }
        if self.peer.persistent_keepalive_interval != peer.persistent_keepalive_interval {
            self.peer.persistent_keepalive_interval = peer.persistent_keepalive_interval;
            self.persistent_keepalive_interval_changed(emitter).await?;
        }
        if self.peer.last_handshake_time != peer.last_handshake_time {
            self.peer.last_handshake_time = peer.last_handshake_time;
            self.last_handshake_time_changed(emitter).await?;
        }
        if self.peer.rx_bytes != peer.rx_bytes {
            self.peer.rx_bytes = peer.rx_bytes;
        }
        if self.peer.tx_bytes != peer.tx_bytes {
            self.peer.tx_bytes = peer.tx_bytes;
        }
        if self.peer.allowed_ips != peer.allowed_ips {
            self.peer.allowed_ips = peer.allowed_ips.clone();
            self.allowed_ips_changed(emitter).await?;
        }
        if self.peer.protocol_version != peer.protocol_version {
            self.peer.protocol_version = peer.protocol_version;
            self.protocol_version_changed(emitter).await?;
        }
        Ok(())
    }
}

#[interface(name = "io.github.thokis.WireGuard1.Peer")]
impl Peer {
    #[zbus(property)]
    async fn public_key(&self) -> String {
        STANDARD.encode(self.peer.public_key)
    }

    #[zbus(property)]
    async fn endpoint(&self) -> String {
        match self.peer.endpoint {
            Some(socket_addr) => socket_addr.to_string(),
            None => "".to_string(),
        }
    }

    #[zbus(property)]
    async fn persistent_keepalive_interval(&self) -> u16 {
        self.peer.persistent_keepalive_interval
    }

    #[zbus(property)]
    async fn last_handshake_time(&self) -> u64 {
        self.peer.last_handshake_time.as_secs()
    }

    #[zbus(property(emits_changed_signal = "false"))]
    async fn rx_bytes(&self) -> u64 {
        self.peer.rx_bytes
    }

    #[zbus(property(emits_changed_signal = "false"))]
    async fn tx_bytes(&self) -> u64 {
        self.peer.tx_bytes
    }

    #[zbus(property)]
    async fn allowed_ips(&self) -> Vec<String> {
        self.peer
            .allowed_ips
            .iter()
            .map(|allowed_ip| format!("{}/{}", allowed_ip.ipaddr, allowed_ip.cidr_mask))
            .collect()
    }

    #[zbus(property)]
    async fn protocol_version(&self) -> u32 {
        self.peer.protocol_version
    }
}
