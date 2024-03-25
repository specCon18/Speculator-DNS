mod message;
mod server;

use std::net::Ipv4Addr;
use server::DNSResolver;

fn main() -> Result<(),std::io::Error>{

    // Instanciate Resolver
    let resolver:DNSResolver = match DNSResolver::new(Ipv4Addr::new(0,0,0,0), 2053) {
        Ok(s) => s,
        Err(e) => return Err(e),
    };

    // For now, queries are handled sequentially, so an infinite loop for servicing
    // requests is initiated.
    loop {
        match DNSResolver::handle_query(&resolver) {
            Ok(_) => {},
            Err(e) => eprintln!("An error occurred: {}", e),
        }
    }
}
