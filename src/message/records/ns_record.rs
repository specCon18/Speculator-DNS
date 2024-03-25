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

/// Represents a DNS NS (Name Server) record.
///
/// NS records are used to specify the authoritative name servers for a domain, 
/// facilitating the delegation of DNS responsibilities to specific servers. 
/// This struct encapsulates the data related to an NS record, including the domain 
/// name of the authoritative name server.
#[derive(Debug, PartialEq, Eq)]
pub struct DNSNSRecord {
    /// Common DNS record preamble containing metadata such as the domain name, record type, class, and TTL.
    pub preamble: DNSRecordPreamble,
    /// The domain name of the authoritative name server for the domain.
    pub rdata: String,
}

impl DNSRecordTrait for DNSNSRecord {
    /// Reads a DNS NS record from the provided byte buffer and constructs a `DNSNSRecord` instance.
    ///
    /// # Parameters
    /// - `buffer`: A mutable reference to a `BytePacketBuffer` from which the record will be read.
    /// - `domain`: The domain name associated with the record.
    /// - `qclass`: The class of the DNS query, typically `IN` for internet.
    /// - `ttl`: The Time To Live (TTL) value for the DNS record.
    /// - `_data_len`: The length of the data section of the record. Unused in this implementation.
    ///
    /// # Returns
    /// - `Ok(DNSRecord)` containing the newly constructed `DNSNSRecord`.
    /// - `Err(std::io::Error)` if there is an error reading from the buffer.
    fn read(buffer: &mut BytePacketBuffer, domain: String, qclass: QRClass, ttl: u32, _data_len: u16) -> Result<DNSRecord, std::io::Error> {
        let mut ns_domain: String = String::new();
        match buffer.read_qname(&mut ns_domain) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        Ok(DNSRecord::NS(DNSNSRecord::new(domain,qclass, ttl, ns_domain)))
    }
    //TODO: Call DNSRecordPreamble::new().write(buffer)
    /// Writes this DNS NS record to the given byte buffer.
    ///
    /// This method serializes the NS record into a byte format, including the domain name 
    /// of the authoritative name server. It also dynamically calculates the `rdlength` field 
    /// based on the length of the serialized domain name.
    ///
    /// # Parameters
    /// - `buffer`: A mutable reference to a `BytePacketBuffer` where the record will be serialized.
    ///
    /// # Returns
    /// - `Ok(())` on successful serialization.
    /// - `Err(std::io::Error)` if an error occurs during writing.
    fn write(&self, buffer: &mut BytePacketBuffer) -> Result<(), std::io::Error> {
        match buffer.write_qname(&self.preamble.name) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match buffer.write_u16(self.preamble.rtype.to_u16()) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match buffer.write_u16(QRClass::to_u16(&self.preamble.class)) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match buffer.write_u32(self.preamble.ttl) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
    
        let len_pos:usize = buffer.pos(); // Remember the position to write the length later
        match buffer.write_u16(0) {
            Ok(s) => s,
            Err(e) => return Err(e),
        }; // Placeholder for RDLENGTH
    
        let start_pos:usize = buffer.pos(); // Start position of RDATA
        match buffer.write_qname(&self.rdata) {
            Ok(s) => s,
            Err(e) => return Err(e),
        }; // Write the domain name of the name server
        let end_pos:usize = buffer.pos(); // End position of RDATA
    
        let rdlength:usize = end_pos - start_pos; // Calculate RDLENGTH
        match buffer.seek(len_pos) {
            Ok(s) => s,
            Err(e) => return Err(e),
        }; // Go back to write RDLENGTH
        match buffer.write_u16(rdlength as u16) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match buffer.seek(end_pos) {
            Ok(s) => s,
            Err(e) => return Err(e),
        }; // Move back to the end of the RDATA
        Ok(())
    }
}

impl DNSNSRecord {
    /// Constructs a new `DNSNSRecord`.
    ///
    /// This method creates a new NS record with the specified domain name, class, TTL, 
    /// and the domain name of the authoritative name server.
    ///
    /// # Parameters
    /// - `name`: The domain name associated with the record.
    /// - `class`: The class of the DNS record, typically `IN` for internet.
    /// - `ttl`: The time-to-live value for the record, indicating how long it should be cached.
    /// - `ns_domain`: The domain name of the authoritative name server.
    ///
    /// # Returns
    /// A new instance of `DNSNSRecord`.
    fn new(name: String, class: QRClass, ttl: u32, ns_domain:String) -> Self {
        DNSNSRecord {
            preamble: DNSRecordPreamble {
                name,
                rtype: QRType::NS, // The type code for an NS record is 2
                class, // The class for Internet is 1 (IN)
                ttl,
                rdlength:ns_domain.len() as u16 // Length of the domain name in bytes
            },
            rdata: ns_domain,
        }        
    }
}