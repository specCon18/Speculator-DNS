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

/// Represents a DNS MX (Mail Exchange) record.
///
/// MX records are used to specify the mail servers responsible for accepting email messages
/// on behalf of a domain, providing a mechanism for email delivery targeting. This struct
/// encapsulates the MX record data including the preference and mail exchange domain.
#[derive(Debug, PartialEq, Eq)]
pub struct DNSMXRecord {
    /// Common DNS record preamble containing metadata such as domain name, record type, class, and TTL (Time To Live).
    pub preamble: DNSRecordPreamble,
    /// The preference value of the MX record, used to prioritize mail delivery when multiple MX records are present.
    /// Lower values are preferred.
    pub preference: u16,
    /// The domain name of the mail exchange server. This value specifies the target host for email messages sent to the domain.
    pub exchange: String,
}

impl DNSRecordTrait for DNSMXRecord {
    /// Reads a DNS MX record from the provided byte buffer and constructs a `DNSMXRecord` instance.
    ///
    /// # Parameters
    /// - `buffer`: A mutable reference to a `BytePacketBuffer` from which the record data will be read.
    /// - `domain`: The domain name associated with the record.
    /// - `qclass`: The class of the DNS query, typically `IN` for internet.
    /// - `ttl`: The Time To Live (TTL) value for the DNS record.
    /// - `_data_len`: The length of the data in the record. Unused in this implementation.
    ///
    /// # Returns
    /// - `Ok(DNSRecord)` containing the newly constructed `DNSMXRecord`.
    /// - `Err(std::io::Error)` if there is an error reading from the buffer.
    fn read(buffer: &mut BytePacketBuffer, domain: String, qclass: QRClass, ttl: u32, _data_len: u16) -> Result<DNSRecord, std::io::Error> {
        let preference: u16 = match buffer.read_u16() {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        let mut exchange: String = String::new();
        match buffer.read_qname(&mut exchange) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        
        let rdata:(u16,String) = (preference,exchange);

        Ok(DNSRecord::MX(DNSMXRecord::new(domain, qclass, ttl, rdata)))
    }
    //TODO: Call DNSRecordPreamble::new().write(buffer)
    /// Writes this DNS MX record to the given byte buffer.
    ///
    /// This method serializes the MX record into the buffer, including both the record preamble
    /// and the specific fields for the MX record such as the preference and the mail exchange domain.
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
        match buffer.write_u16(self.preference) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match buffer.write_qname(&self.exchange) {
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

impl DNSMXRecord {
    /// Constructs a new `DNSMXRecord`.
    ///
    /// This method initializes a DNS MX record with the given domain name, class, TTL,
    /// preference, and mail exchange domain.
    ///
    /// # Parameters
    /// - `name`: The domain name associated with the record.
    /// - `class`: The class of the DNS record, typically `IN` for internet.
    /// - `ttl`: The time-to-live value for the record, indicating how long it should be cached.
    /// - `rdata`: A tuple containing the preference and the mail exchange domain for the MX record.
    ///
    /// # Returns
    /// A new instance of `DNSMXRecord`.
    fn new(name: String, class: QRClass, ttl: u32, rdata:(u16, String)) -> Self {
        return DNSMXRecord {
            preamble: DNSRecordPreamble::new(name, QRType::MX, class, ttl, 0), // rdlength will be set later
            preference: rdata.0,
            exchange: rdata.1,
        };
    }
}