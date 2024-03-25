use std::{
    time::{
        SystemTime,
        UNIX_EPOCH
    },
    net::{
        Ipv4Addr,
        SocketAddrV4,
        UdpSocket
    }
};

use crate::message::{
    byte_packet_buffer::BytePacketBuffer,
    header::{QRFlag, RAFlag, RDFlag,RCode},
    DNSPacket,
    DNSQuestion,
    QRClass,
    QRType
};

type Port = u16;
/// Represents a DNS resolver with capabilities to perform DNS queries using UDP.
pub struct DNSResolver {
    /// The UDP socket through which the DNS queries are sent and received.
    socket: UdpSocket
}

impl DNSResolver {
    /// Constructs a new `DNSResolver` instance bound to the specified IP address and port.
    ///
    /// # Arguments
    ///
    /// * `ip` - An `Ipv4Addr` representing the IP address to bind the UDP socket to.
    /// * `port` - A `Port` (u16) representing the port number to bind the UDP socket to.
    ///
    /// # Returns
    ///
    /// Returns a `Result` which is:
    /// - `Ok` containing the `DNSResolver` instance if the socket is successfully bound.
    /// - `Err` containing the `std::io::Error` if the socket fails to bind.
    pub fn new(ip:Ipv4Addr,port:Port) -> Result<Self, std::io::Error> {
        let socket_address:SocketAddrV4 = SocketAddrV4::new(ip,port);
        let socket = match UdpSocket::bind(socket_address) {
            Ok(s) => s,
            Err(e) => return Err(e)
        };
        Ok(Self { socket })
    }

    /// Generates a pseudo-random packet ID using a simple XOR shift technique.
    ///
    /// # Returns
    ///
    /// Returns a `u16` representing the generated packet ID.
    fn generate_packet_id() -> u16{
        let seed:u64 = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_micros() as u64;
        // Simple pseudo-random number generation using XOR shift technique.
        let mut rng:u64 = seed ^ (seed << 21);
        rng ^= rng >> 35;
        rng ^= rng << 4;
        let random_value:u16 = (rng % u16::MAX as u64) as u16;
        return random_value
    }

    /// Performs a DNS lookup by sending a query to the specified DNS server and awaiting the response.
    ///
    /// # Arguments
    ///
    /// * `qname` - A string slice (`&str`) representing the domain name to query.
    /// * `qtype` - A `QRType` representing the type of the DNS query.
    /// * `qclass` - A `QRClass` representing the class of the DNS query.
    /// * `server` - A tuple containing the server's `Ipv4Addr` and port number (`u16`).
    ///
    /// # Returns
    ///
    /// Returns a `Result` which is:
    /// - `Ok` containing the received `DNSPacket` if the query was successful.
    /// - `Err` containing the `std::io::Error` if there was an error sending or receiving the packet.
    pub fn lookup(&self, qname: &str, qtype: QRType, qclass: QRClass, server: (Ipv4Addr, u16)) -> Result<DNSPacket, std::io::Error> {
        let mut packet: DNSPacket = DNSPacket::new();
        packet.header.id = DNSResolver::generate_packet_id();
        packet.header.qdcount = 1;
        packet.header.rd = RDFlag::NonDesired;
        packet.question.questions.push(DNSQuestion::new(qname.to_string(), qtype, qclass));

        let mut req_buffer:BytePacketBuffer = BytePacketBuffer::new();
        match packet.write(&mut req_buffer) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match self.socket.send_to(&req_buffer.buf[0..req_buffer.pos], server) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        let mut res_buffer:BytePacketBuffer = BytePacketBuffer::new();
        match self.socket.recv_from(&mut res_buffer.buf) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        DNSPacket::from_buffer(&mut res_buffer)
    }


    /// Performs a recursive DNS lookup, starting at a predefined root server.
    ///
    /// # Arguments
    ///
    /// * `qname` - A string slice (`&str`) representing the domain name to recursively resolve.
    /// * `qtype` - A `QRType` representing the type of the DNS query.
    ///
    /// # Returns
    ///
    /// Returns a `Result` which is:
    /// - `Ok` containing the resolved `DNSPacket` if the recursive lookup was successful.
    /// - `Err` containing the `std::io::Error` if there was an error during the lookup process.
    fn recursive_lookup(&self, qname: &str, qtype: QRType) -> Result<DNSPacket, std::io::Error> {
        // Initial DNS server to start the recursive search
        // In a full implementation, this would start at a root server
        let mut server: (Ipv4Addr, u16) = ("1.1.1.1".parse().unwrap(), 53);

        loop {
            println!("Attempting lookup of {:?} {} with server {:?}", qtype, qname, server.0);

            // Send query to the current server
            let response:DNSPacket = match self.lookup(qname, qtype, QRClass::IN, server) {
                Ok(s) => s,
                Err(e) => return Err(e),
            };

            // Check for answers in the response; if found, return the response
            if !response.answer.answers.is_empty() && response.header.rcode == RCode::NoError {
                return Ok(response);
            }

            // Handle NXDomain (non-existent domain) response
            if response.header.rcode == RCode::NXDomain {
                return Ok(response);
            }

            // If the response does not contain an answer but has authoritative nameservers,
            // try to resolve one of the NS records to find the next server to query.
            if let Some(new_server) = self.find_next_server(&response) {
                server = new_server;
                continue;
            }

            // If unable to find a next server or resolve the query, return the last response
            return Ok(response);
        }
    }

    /// Finds the next server to query based on NS records from the response packet.
    ///
    /// # Arguments
    ///
    /// * `response` - A reference to a `DNSPacket` containing the response from a DNS query.
    ///
    /// # Returns
    ///
    /// Returns an `Option` which is:
    /// - `Some` containing a tuple of the next server's `Ipv4Addr` and port number if found.
    /// - `None` if no next server could be resolved.
    fn find_next_server(&self, response: &DNSPacket) -> Option<(Ipv4Addr, u16)> {
        // Iterate over NS records in the Authority section to find the domain name of the nameserver
        for (_ns_domain, ns_host) in response.get_ns("") {
            // Attempt to resolve the NS host to an IP address using the Additional section
            if let Some(ip_addr) = response.get_resolved_ns(ns_host) {
                // If an IP address for the NS is found, return it
                return Some((ip_addr, 53)); // DNS standard port
            } else {
                // If the NS host's IP address isn't in the Additional section, perform a recursive lookup
                // This branch can potentially cause recursion issues if not handled carefully
                if let Ok(packet) = self.recursive_lookup(ns_host, QRType::A) {
                    if let Some(ip_addr) = packet.get_random_a() {
                        // If the recursive lookup successfully finds the IP address, return it
                        return Some((ip_addr, 53));
                    }
                }
            }
        }
        // If no suitable NS record is found or resolved, return None
        None
    }
    
    /// Handles a single incoming DNS query packet, processes it, and sends back a response.
    ///
    /// # Returns
    ///
    /// Returns a `Result` which is:
    /// - `Ok` if the query was successfully processed and a response was sent.
    /// - `Err` containing the `std::io::Error` if there was an error processing the query or sending the response.
    pub fn handle_query(&self) -> Result<(), std::io::Error> {

        let mut req_buffer: BytePacketBuffer = BytePacketBuffer::new();

        // Use the DNSResolver's own socket to receive data
        let (_, src) = match self.socket.recv_from(&mut req_buffer.buf) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        let mut request = match DNSPacket::from_buffer(&mut req_buffer) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        let mut response_packet: DNSPacket = DNSPacket::new();
        response_packet.header.id = request.header.id;
        response_packet.header.rd = RDFlag::Desired;
        response_packet.header.ra = RAFlag::Available;
        response_packet.header.qr = QRFlag::Response;

        if let Some(question) = request.question.questions.pop() {
            println!("Received query: {:?}", question);

            match self.recursive_lookup(&question.qname, question.qtype) {
                Ok(result) => {
                    response_packet.question.questions.push(question.clone());
                    response_packet.header.rcode = result.header.rcode;

                    for rec in result.answer.answers {
                        println!("Answer: {:?}", rec);
                        response_packet.answer.answers.push(rec);
                    }
                    for rec in result.authority.records {
                        println!("Authority: {:?}", rec);
                        response_packet.authority.records.push(rec);
                    }
                    for rec in result.additional.records {
                        println!("Resource: {:?}", rec);
                        response_packet.additional.records.push(rec);
                    }
                },
                Err(_) => {
                    response_packet.header.rcode = RCode::ServFail;
                }
            }
        } else {
            response_packet.header.rcode = RCode::FormErr;
        }

        // Prepare the response and use the DNSResolver's own socket to send it
        let mut res_buffer: BytePacketBuffer = BytePacketBuffer::new();
        match response_packet.write(&mut res_buffer) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        let len: usize = res_buffer.pos();
        let data = res_buffer.get_byte_range(0, len)?;

        match self.socket.send_to(data, src) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        Ok(())
    }
}

