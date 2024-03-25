use crate::message::{
    records::{
        DNSRecordPreamble,
        DNSRecordTrait
    },
    BytePacketBuffer,
    QRClass,
    QRType,
    DNSRecord
};
use std::net::Ipv6Addr;

/// Represents a DNS AAAA record.
///
/// DNS AAAA records are used to map domain names to IPv6 addresses. This struct
/// encapsulates the data related to such a record, including the common preamble
/// and the IPv6 address.
#[derive(Debug, PartialEq, Eq)]
pub struct DNSAAAARecord {
    /// The common preamble for DNS records, containing metadata such as the domain name,
    /// record type, class, and time-to-live (TTL) value.
    pub preamble: DNSRecordPreamble,
    /// The IPv6 address associated with the domain name.
    pub address: Ipv6Addr,
}

impl DNSRecordTrait for DNSAAAARecord {
    /// Reads a DNS AAAA record from the provided buffer, constructing a new instance of `DNSAAAARecord`.
    ///
    /// # Parameters
    /// - `buffer`: A mutable reference to a `BytePacketBuffer` from which the record data will be read.
    /// - `domain`: The domain name associated with the record.
    /// - `qclass`: The class of the DNS query.
    /// - `ttl`: The time-to-live value for the DNS record.
    /// - `_data_len`: The length of the data section of the record (not used directly in this implementation).
    ///
    /// # Returns
    /// A `Result` which is:
    /// - `Ok(DNSRecord)` containing the newly constructed `DNSAAAARecord` if reading succeeds.
    /// - `Err(std::io::Error)` if there is an error during reading from the buffer.
    fn read(buffer: &mut BytePacketBuffer, domain: String, qclass: QRClass, ttl: u32, _data_len: u16) -> Result<DNSRecord, std::io::Error> {
        let raw_addr = match buffer.read_u128() {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        let address:Ipv6Addr = Ipv6Addr::new(
            ((raw_addr >> 112) & 0xFFFF) as u16,
            ((raw_addr >> 96) & 0xFFFF) as u16,
            ((raw_addr >> 80) & 0xFFFF) as u16,
            ((raw_addr >> 64) & 0xFFFF) as u16,
            ((raw_addr >> 48) & 0xFFFF) as u16,
            ((raw_addr >> 32) & 0xFFFF) as u16,
            ((raw_addr >> 16) & 0xFFFF) as u16,
            ((raw_addr >> 0) & 0xFFFF) as u16,
        );
        Ok(DNSRecord::AAAA(DNSAAAARecord::new(domain,qclass, ttl, address)))
    }

    /// Writes the DNS AAAA record into the given buffer.
    ///
    /// # Parameters
    /// - `buffer`: A mutable reference to a `BytePacketBuffer` into which the record will be serialized.
    ///
    /// # Returns
    /// A `Result` indicating the outcome of the write operation:
    /// - `Ok(())` on success.
    /// - `Err(std::io::Error)` if an error occurs during writing.
    fn write(&self, buffer: &mut BytePacketBuffer) -> Result<(), std::io::Error> {
        match DNSRecordPreamble::new((*self.preamble.name).to_string(), self.preamble.rtype, self.preamble.class, self.preamble.ttl, 16).write(buffer) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match buffer.write_u128(self.address.into()) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        Ok(())
    }
}

impl DNSAAAARecord {
    /// Constructs a new `DNSAAAARecord`.
    ///
    /// # Parameters
    /// - `name`: The domain name associated with the record.
    /// - `class`: The class of the DNS record, typically `IN` for internet.
    /// - `ttl`: The time-to-live value for the record, indicating how long it should be cached.
    /// - `address`: The IPv6 address to be associated with the domain name.
    ///
    /// # Returns
    /// A new instance of `DNSAAAARecord`.
    fn new(name: String, class: QRClass, ttl: u32, address:Ipv6Addr) -> Self {
        DNSAAAARecord {
            preamble: DNSRecordPreamble::new(name, QRType::AAAA, class, ttl, 16), // IPv6 addresses are 16 bytes
            address,
        }
    }
}