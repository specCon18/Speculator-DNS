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

/// Represents a DNS CNAME (Canonical Name) record.
///
/// A CNAME record maps a domain name (alias) to the true or canonical domain name. 
/// This struct encapsulates a DNS record that contains the alias name and points to the canonical domain name.
#[derive(Debug, PartialEq, Eq)]
pub struct DNSCNAMERecord {
    /// Common DNS record preamble containing metadata such as domain name, record type, class, and TTL (Time To Live).
    pub preamble: DNSRecordPreamble,
    /// The canonical domain name that the DNS query's domain name alias points to.
    pub rdata: String
}

impl DNSRecordTrait for DNSCNAMERecord {
    /// Reads a DNS CNAME record from the given byte buffer and constructs a `DNSCNAMERecord` instance.
    ///
    /// # Parameters
    /// - `buffer`: A mutable reference to a `BytePacketBuffer` from which the record will be read.
    /// - `domain`: The domain name associated with the record.
    /// - `qclass`: The class of the DNS query, typically `IN` for internet.
    /// - `ttl`: The Time To Live (TTL) value for the DNS record.
    /// - `_data_len`: The length of the data in the record. Unused in this implementation.
    ///
    /// # Returns
    /// - `Ok(DNSRecord)` containing the newly constructed `DNSCNAMERecord`.
    /// - `Err(std::io::Error)` if there is an error reading from the buffer.
    fn read(buffer: &mut BytePacketBuffer, domain: String, qclass: QRClass, ttl: u32, _data_len: u16) -> Result<DNSRecord, std::io::Error> {
        let mut canonical_name: String = String::new();
        match buffer.read_qname(&mut canonical_name) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        Ok(DNSRecord::CNAME(DNSCNAMERecord::new(domain,qclass, ttl, canonical_name)))
    }

    //TODO: rewrite to step the buffer the length of the preamble then run the logic to derive rdlength then call DNSRecordPreamble::new()
    //TODO: Consider adding the rdlength parsing logic to DNSRecordPreamble::write()
    //TODO: Call DNSRecordPreamble::new().write(buffer)
    /// Writes this DNS CNAME record to the given byte buffer.
    ///
    /// # Implementation Notes
    /// This method serializes the CNAME record into a byte format, first writing the record's preamble
    /// and then the canonical domain name. It also updates the `rdlength` field based on the length of
    /// the canonical name.
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
        // Placeholder position for length
        let len_pos:usize = buffer.pos();
        match buffer.write_u16(0) {
            Ok(s) => s,
            Err(e) => return Err(e),
        }; // Placeholder for length

        let start_pos:usize = buffer.pos();
        match buffer.write_qname(&self.rdata) {
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

impl DNSCNAMERecord {
    /// Constructs a new `DNSCNAMERecord`.
    ///
    /// This method creates a new CNAME record with the specified domain name, class, TTL, and canonical name.
    ///
    /// # Parameters
    /// - `name`: The domain name associated with the record (alias name).
    /// - `class`: The class of the DNS record, typically `IN` for internet.
    /// - `ttl`: The time-to-live value for the record, indicating how long it should be cached.
    /// - `canonical_name`: The canonical domain name to which the alias name points.
    ///
    /// # Returns
    /// A new instance of `DNSCNAMERecord`.
    fn new(name: String, class: QRClass, ttl: u32, canonical_name:String) -> Self {
        DNSCNAMERecord {
            preamble: DNSRecordPreamble {
                name,
                rtype: QRType::CNAME, // The type code for a CNAME record is 5
                class, // The class for Internet is 1 (IN)
                ttl,
                rdlength:canonical_name.len() as u16, // Length of the canonical name in bytes
            },
            rdata: canonical_name,
        }
    }
}