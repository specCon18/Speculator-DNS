mod message;
mod server;

use std::net::UdpSocket;

fn main() -> Result<(),std::io::Error>{
    // Bind an UDP socket on port 2053
    let socket = UdpSocket::bind(("0.0.0.0", 2053))?;

    // For now, queries are handled sequentially, so an infinite loop for servicing
    // requests is initiated.
    loop {
        match server::handle_query(&socket) {
            Ok(_) => {},
            Err(e) => eprintln!("An error occurred: {}", e),
        }
    }
}
