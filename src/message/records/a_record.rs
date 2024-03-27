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
use std::net::Ipv4Addr;

/// Represents a DNS A record.
///
/// This record maps a domain name to an IPv4 address. 
#[derive(Debug, PartialEq, Eq)]
pub struct DNSARecord {
    /// The common preamble for all DNS records.
    ///
    /// It contains metadata such as the domain name, record type, class, and TTL.
    pub preamble: DNSRecordPreamble,
    /// The IPv4 address associated with the domain name.
    pub rdata: std::net::Ipv4Addr,
}

impl DNSRecordTrait for DNSARecord {
    /// Reads a DNS A record from the given buffer, constructing a new instance.
    ///
    /// # Parameters
    /// - `buffer`: A mutable reference to a `BytePacketBuffer` containing the raw data.
    /// - `domain`: The domain name associated with the record.
    /// - `qclass`: The class of the query.
    /// - `ttl`: The time-to-live value for the record.
    /// - `_data_len`: The length of the record data.
    ///
    /// # Returns
    /// A result containing either the new DNS A record or an I/O error if reading fails.
    fn read(buffer: &mut BytePacketBuffer, domain: String, qclass: QRClass, ttl: u32, _data_len: u16) -> Result<DNSRecord, std::io::Error>{
        let raw_addr: u32 = match buffer.read_u32() {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        let addr: Ipv4Addr = Ipv4Addr::new(
            ((raw_addr >> 24) & 0xFF) as u8,
            ((raw_addr >> 16) & 0xFF) as u8,
            ((raw_addr >> 8) & 0xFF) as u8,
            ((raw_addr >> 0) & 0xFF) as u8,
        );

        Ok(DNSRecord::A(DNSARecord::new(domain,qclass,ttl,addr)))
    }
    /// Writes the DNS A record to the given buffer.
    ///
    /// This method serializes the DNS A record into a byte format suitable for network transmission or storage.
    /// It first writes the preamble information, which includes the domain name, record type, class, and time-to-live (TTL) value,
    /// and then writes the IPv4 address associated with the domain name.
    ///
    /// # Parameters
    /// - `buffer`: A mutable reference to a `BytePacketBuffer` where the serialized data will be written.
    ///
    /// # Returns
    /// - `Ok(())` if the write operation is successful,
    /// - `Err(std::io::Error)` if there is an error during the write operation.
    ///
    /// # Examples
    /// ```
    /// # use std::net::Ipv4Addr;
    /// # use your_crate::{BytePacketBuffer, DNSARecord, QRClass, DNSRecordTrait};
    /// # let mut buffer = BytePacketBuffer::new();
    /// # let record = DNSARecord::new(
    /// #     "example.com".to_string(),
    /// #     QRClass::IN,
    /// #     3600,
    /// #     Ipv4Addr::new(127, 0, 0, 1),
    /// # );
    /// let result = record.write(&mut buffer);
    /// assert!(result.is_ok());
    /// ```
    ///
    /// # Errors
    /// This method returns an `Err` variant of `Result` containing an `std::io::Error` if:
    /// - There is an error writing the preamble to the buffer,
    /// - There is an error writing the IPv4 address to the buffer.
    ///
    /// It is important to handle these errors appropriately to ensure reliable operation of the DNS system.
    fn write(&self, buffer: &mut BytePacketBuffer) -> Result<(), std::io::Error> {
        match DNSRecordPreamble::new((*self.preamble.name).to_string(), self.preamble.rtype, self.preamble.class, self.preamble.ttl, 4).write(buffer) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        // Write the IPv4 address
        let octets = self.rdata.octets();
        for octet in octets.iter() {
            match buffer.write_u8(*octet) {
                Ok(s) => s,
                Err(e) => return Err(e.into()),
            };
        }
        Ok(())
    }
}

impl DNSARecord {
    /// Creates a new `DNSARecord`.
    ///
    /// # Parameters
    /// - `name`: The domain name associated with the record.
    /// - `class`: The class of the DNS record.
    /// - `ttl`: The time-to-live value for the record.
    /// - `rdata`: The IPv4 address associated with the domain name.
    ///
    /// # Returns
    /// A new instance of `DNSARecord`.
    fn new(name: String, class: QRClass, ttl: u32, rdata:Ipv4Addr) -> Self {
        DNSARecord {
            preamble: DNSRecordPreamble::new(name, QRType::A, class, ttl, 4),
            rdata,
        }
    }
}