mod message;
mod server;

use std::net::Ipv4Addr;
use server::DNSResolver;

/// The entry point of the DNS server.
///
/// Initializes a `DNSResolver` to listen for incoming DNS queries on a specified address and port.
/// It enters an infinite loop, handling each incoming DNS query sequentially.
///
/// # Errors
///
/// If the `DNSResolver` fails to initialize (e.g., due to a problem binding to the specified address and port),
/// the function will return an `Err` containing the `std::io::Error` encountered during initialization.
///
/// # Example
///
/// To run a DNS server listening on all interfaces at port 2053, simply execute:
/// ```
/// cargo run
/// ```
///
/// This assumes that `cargo run` is being used to compile and execute the Rust program where this main function resides.
///
/// # Remarks
///
/// In its current implementation, the server handles DNS queries sequentially, which may not be optimal for
/// high-throughput scenarios. Future improvements could include handling queries concurrently or asynchronously
/// to increase the number of queries that can be serviced simultaneously.
fn main() -> Result<(),std::io::Error>{
    // Initialize a DNSResolver to listen on 0.0.0.0:2053. This IP and port configuration allows the server
    // to accept DNS queries on all interfaces on port 2053.
    let resolver:DNSResolver = match DNSResolver::new(Ipv4Addr::new(0,0,0,0), 2053) {
        Ok(s) => s,
        Err(e) => return Err(e),
    };

    // The server enters an infinite loop, listening for and handling incoming DNS queries.
    loop {
        match DNSResolver::handle_query(&resolver) {
            Ok(_) => {
                // If a query is handled successfully, continue listening for the next query.
            },
            Err(e) => {
                // Log any errors encountered while handling a query, but do not exit the loop.
                // This allows the server to continue operating even if individual queries fail.
                eprintln!("An error occurred: {}", e)
            }
        }
    }
}
