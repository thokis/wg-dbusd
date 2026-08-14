use base64::{Engine as _, engine::general_purpose::STANDARD};
use env_logger::Env;
use std::net::SocketAddr;
use std::time::Duration;
use std::{error::Error, future::pending};
use wireguard_uapi::get::*;
use wireguard_uapi::linux::{DeviceInterface, RouteSocket, WgSocket};
use zbus::{connection, interface};

const BUS_NAME: &str = "io.github.thokis.WireGuard1";
const OBJECT_PATH: &str = "/io/github/thokis/WireGuard1";

#[derive(Clone, Debug)]
struct Peer {
    public_key: [u8; 32],
    // preshared_key: [u8; 32],
    endpoint: String,
    persistent_keepalive_interval: u16,
    last_handshake_time: Duration,
    rx_bytes: u64,
    tx_bytes: u64,
    allowed_ips: Vec<String>,
    protocol_version: u32,
}

impl From<wireguard_uapi::get::Peer> for Peer {
    fn from(peer: wireguard_uapi::get::Peer) -> Self {
        Peer {
            public_key: peer.public_key,
            // preshared_key: peer.preshared_key,
            endpoint: parse_optional_socket_addr_to_string(peer.endpoint),
            persistent_keepalive_interval: peer.persistent_keepalive_interval,
            last_handshake_time: peer.last_handshake_time,
            rx_bytes: peer.rx_bytes,
            tx_bytes: peer.tx_bytes,
            allowed_ips: map_vec_allowed_ip_to_vec_string(peer.allowed_ips),
            protocol_version: peer.protocol_version,
        }
    }
}

#[derive(Debug)]
struct Device {
    ifindex: u32,
    ifname: String,
    public_key: Option<[u8; 32]>,
    // private_key: Option<[u8; 32]>,
    listen_port: u16,
    fwmark: u32,
    peers: Vec<Peer>,
}

impl From<wireguard_uapi::get::Device> for Device {
    fn from(device: wireguard_uapi::get::Device) -> Self {
        Device {
            ifindex: device.ifindex,
            ifname: device.ifname,
            public_key: device.public_key,
            // private_key: device.private_key,
            listen_port: device.listen_port,
            fwmark: device.fwmark,
            peers: device.peers.into_iter().map(|peer| peer.into()).collect(),
        }
    }
}

#[interface(name = "io.github.thokis.WireGuard1.Peer")]
impl Peer {
    #[zbus(property)]
    async fn public_key(&self) -> String {
        STANDARD.encode(self.public_key)
    }

    #[zbus(property)]
    async fn endpoint(&self) -> &str {
        &self.endpoint
    }

    #[zbus(property)]
    async fn persistent_keepalive_interval(&self) -> u16 {
        self.persistent_keepalive_interval
    }

    #[zbus(property)]
    async fn last_handshake_time(&self) -> u64 {
        self.last_handshake_time.as_secs()
    }

    #[zbus(property(emits_changed_signal = "false"))]
    async fn rx_bytes(&self) -> u64 {
        self.rx_bytes
    }

    #[zbus(property(emits_changed_signal = "false"))]
    async fn tx_bytes(&self) -> u64 {
        self.tx_bytes
    }

    #[zbus(property)]
    async fn allowed_ips(&self) -> &[String] {
        &self.allowed_ips
    }

    #[zbus(property)]
    async fn protocol_version(&self) -> u32 {
        self.protocol_version
    }
}

#[interface(name = "io.github.thokis.WireGuard1.Device")]
impl Device {
    #[zbus(property(emits_changed_signal = "const"))]
    async fn if_index(&self) -> u32 {
        self.ifindex
    }
    #[zbus(property(emits_changed_signal = "const"))]
    async fn if_name(&self) -> &str {
        &self.ifname
    }

    #[zbus(property)]
    async fn public_key(&self) -> String {
        encode_optional_bytes_to_base64(self.public_key)
    }

    #[zbus(property)]
    async fn listen_port(&self) -> u16 {
        self.listen_port
    }

    #[zbus(property)]
    async fn fw_mark(&self) -> u32 {
        self.fwmark
    }
}

fn encode_optional_bytes_to_base64(optional_bytes: Option<[u8; 32]>) -> String {
    match optional_bytes {
        Some(bytes) => STANDARD.encode(bytes),
        None => "".to_string(),
    }
}

fn map_vec_allowed_ip_to_vec_string(allowed_ips: Vec<AllowedIp>) -> Vec<String> {
    allowed_ips
        .into_iter()
        .map(|allowed_ip| format!("{}/{}", allowed_ip.ipaddr, allowed_ip.cidr_mask))
        .collect()
}

fn parse_optional_socket_addr_to_string(optional_socket_addr: Option<SocketAddr>) -> String {
    match optional_socket_addr {
        Some(socket_addr) => socket_addr.to_string(),
        None => "".to_string(),
    }
}

fn setup_logging() -> () {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
}

// Although we use `tokio` here, you can use any async runtime of choice.
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    setup_logging();

    let dbus_system_conn = connection::Builder::system()?
        .name(BUS_NAME)?
        .serve_at(OBJECT_PATH, zbus::fdo::ObjectManager)?
        .build()
        .await?;

    let mut route_socket_conn = RouteSocket::connect()?;
    let mut wg_socket_conn = WgSocket::connect()?;

    for device_name in RouteSocket::list_device_names(&mut route_socket_conn)? {
        if let Ok(device) = WgSocket::get_device(
            &mut wg_socket_conn,
            DeviceInterface::from_name(&device_name),
        ) {
            let device_object = Device::from(device);

            let device_object_path = format!("{}/Devices/{}", OBJECT_PATH, device_name);

            if let Err(e) = dbus_system_conn
                .object_server()
                .at(device_object_path.clone(), device_object)
                .await
            {
                log::error!("could not serve device {device_name} at {device_object_path}: {e}")
            }

            let device = dbus_system_conn
                .object_server()
                .interface::<_, Device>(device_object_path)
                .await?;

            for peer in device.get().await.peers.clone() {
                let peer_name = hex::encode(peer.public_key);

                if let Err(e) = dbus_system_conn
                    .object_server()
                    .at(
                        format!(
                            "{}/Devices/{}/Peers/{}",
                            OBJECT_PATH, device_name, peer_name
                        ),
                        peer,
                    )
                    .await
                {
                    log::error!(
                        "could not serve peer {peer_name} at {OBJECT_PATH}/Devices/{device_name}/Peers/{peer_name}): {e}"
                    )
                }
            }
        } else {
            log::error!("could not get wireguard device from device name \"{device_name}\"")
        };
    }

    pending::<()>().await;

    Ok(())
}
