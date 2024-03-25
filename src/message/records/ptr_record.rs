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

/// Represents a DNS PTR (Pointer) record.
///
/// PTR records are used in reverse DNS lookups to map an IP address to a domain name. 
/// This struct encapsulates the data related to a PTR record, including the domain name 
/// that the IP address points to.
#[derive(Debug, PartialEq, Eq)]
pub struct DNSPTRRecord {
    /// Common DNS record preamble containing metadata such as the domain name, record type, class, and TTL.
    pub preamble: DNSRecordPreamble,
    /// The domain name that the IP address points to in a reverse DNS lookup.
    pub ptrdname: String,
}

impl DNSRecordTrait for DNSPTRRecord {
    /// Reads a DNS PTR record from the provided byte buffer and constructs a `DNSPTRRecord` instance.
    ///
    /// # Parameters
    /// - `buffer`: A mutable reference to a `BytePacketBuffer` from which the record data will be read.
    /// - `domain`: The domain name associated with the record (typically the querying domain in reverse DNS lookups).
    /// - `qclass`: The class of the DNS query, typically `IN` for internet.
    /// - `ttl`: The Time To Live (TTL) value for the DNS record.
    /// - `_data_len`: The length of the data section of the record. Unused in this implementation.
    ///
    /// # Returns
    /// - `Ok(DNSRecord)` containing the newly constructed `DNSPTRRecord`.
    /// - `Err(std::io::Error)` if there is an error reading from the buffer.
    fn read(buffer: &mut BytePacketBuffer, domain: String, qclass: QRClass, ttl: u32, _data_len: u16) -> Result<DNSRecord, std::io::Error> {
        let mut ptrdname: String = String::new();
        match buffer.read_qname(&mut ptrdname) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        Ok(DNSRecord::PTR(DNSPTRRecord::new(domain,qclass, ttl, ptrdname)))
    }

    //TODO: Call DNSRecordPreamble::new().write(buffer)
    /// Writes this DNS PTR record to the given byte buffer.
    ///
    /// This method serializes the PTR record into a byte format, including the domain name 
    /// the IP address points to. It also dynamically calculates the `rdlength` field 
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
        let len_pos:usize = buffer.pos();
        match buffer.write_u16(0) {
            Ok(s) => s,
            Err(e) => return Err(e),
        }; // Placeholder for length

        let start_pos:usize = buffer.pos();
        match buffer.write_qname(&self.ptrdname) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        let end_pos:usize = buffer.pos();
        let rdlength:usize = end_pos - start_pos;
        match buffer.seek(len_pos) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match buffer.write_u16(rdlength as u16) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match buffer.seek(end_pos) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        Ok(())
    }
}

impl DNSPTRRecord {
    /// Constructs a new `DNSPTRRecord`.
    ///
    /// This method creates a new PTR record with the specified domain name, class, TTL, 
    /// and the domain name that the IP address points to in a reverse DNS lookup.
    ///
    /// # Parameters
    /// - `name`: The domain name associated with the record (typically the querying domain in reverse DNS lookups).
    /// - `class`: The class of the DNS record, typically `IN` for internet.
    /// - `ttl`: The time-to-live value for the record, indicating how long it should be cached.
    /// - `ptrdname`: The domain name that the IP address points to.
    ///
    /// # Returns
    /// A new instance of `DNSPTRRecord`.
    fn new(name: String, class: QRClass, ttl: u32, ptrdname:String) -> Self {
        DNSPTRRecord {
            preamble: DNSRecordPreamble::new(name, QRType::PTR, class, ttl, 0), // rdlength will be set later
            ptrdname,
        }
    }
}