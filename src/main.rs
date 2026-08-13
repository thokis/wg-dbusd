use wireguard_uapi::linux::RouteSocket;

fn main() {
    let mut connection = RouteSocket::connect().expect("A");
    let devices = RouteSocket::list_device_names(&mut connection).expect("no devices available");
    println!("{devices:?}");
}
