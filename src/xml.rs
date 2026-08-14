//! The D-Bus introspection XML in `dist/interfaces/` is the published interface
//! contract (feed it to `zbus-xmlgen` for a client proxy). The test below keeps
//! it in sync with the code; regenerate with `REGEN_XML=1 cargo test`.

#[cfg(test)]
mod tests {
    use crate::device::Device;
    use crate::peer::Peer;
    use std::time::Duration;
    use zbus::object_server::Interface;

    const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/dist/interfaces");

    fn dummy_device() -> Device {
        Device::from(wireguard_uapi::get::Device {
            ifindex: 0,
            ifname: "wg0".to_string(),
            private_key: None,
            public_key: None,
            listen_port: 0,
            fwmark: 0,
            peers: vec![],
        })
    }

    fn dummy_peer() -> Peer {
        Peer::from(wireguard_uapi::get::Peer {
            public_key: [0u8; 32],
            preshared_key: [0u8; 32],
            endpoint: None,
            persistent_keepalive_interval: 0,
            last_handshake_time: Duration::ZERO,
            rx_bytes: 0,
            tx_bytes: 0,
            allowed_ips: vec![],
            protocol_version: 1,
        })
    }

    fn node_xml<I: Interface>(iface: &I) -> String {
        let mut body = String::new();
        iface.introspect_to_writer(&mut body, 1);
        format!("<node>\n{body}</node>\n")
    }

    fn check(name: &str, xml: String) {
        std::fs::create_dir_all(DIR).unwrap();
        let path = format!("{DIR}/{name}.xml");
        if std::env::var_os("REGEN_XML").is_some() {
            std::fs::write(&path, xml).unwrap();
        } else {
            let committed = std::fs::read_to_string(&path)
                .unwrap_or_else(|_| panic!("{path} missing — run: REGEN_XML=1 cargo test"));
            assert_eq!(
                committed, xml,
                "{name}.xml is stale — run: REGEN_XML=1 cargo test"
            );
        }
    }

    #[test]
    fn interface_xml_is_current() {
        check("Device", node_xml(&dummy_device()));
        check("Peer", node_xml(&dummy_peer()));
    }
}
