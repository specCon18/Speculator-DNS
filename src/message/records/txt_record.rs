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

/// Represents a DNS TXT (Text) record.
///
/// TXT records are used to hold descriptive text within the DNS system. The text can be
/// used for various purposes, such as providing human-readable information about a server,
/// network, data about a domain, or even security records like SPF or DKIM.
#[derive(Debug, PartialEq, Eq)]
pub struct DNSTXTRecord {
    /// Common DNS record preamble containing metadata such as the domain name, record type, class, and TTL.
    pub preamble: DNSRecordPreamble,
    /// The text content of the TXT record. This field can contain any arbitrary text data.
    pub text: String
}

impl DNSRecordTrait for DNSTXTRecord {
    /// Reads a DNS TXT record from the provided byte buffer and constructs a `DNSTXTRecord` instance.
    ///
    /// # Parameters
    /// - `buffer`: A mutable reference to a `BytePacketBuffer` from which the record data will be read.
    /// - `domain`: The domain name associated with the record.
    /// - `qclass`: The class of the DNS query, typically `IN` for internet.
    /// - `ttl`: The Time To Live (TTL) value for the DNS record.
    /// - `data_len`: The length of the data section of the record, used to read the correct amount of text.
    ///
    /// # Returns
    /// - `Ok(DNSRecord)` containing the newly constructed `DNSTXTRecord`.
    /// - `Err(std::io::Error)` if there is an error reading from the buffer.
    fn read(buffer: &mut BytePacketBuffer, domain: String, qclass: QRClass, ttl: u32, data_len: u16) -> Result<DNSRecord, std::io::Error> {
        let mut i:u16 = 0;
        let mut text: String = String::new();
        while i <= data_len {                    
            text.push(buffer.read_u8()? as char);
            i += 1;
        }
        Ok(DNSRecord::TXT(DNSTXTRecord::new(domain, qclass, ttl, text)))
    }

    //TODO: Call DNSRecordPreamble::new().write(buffer)
    /// Writes this DNS TXT record to the given byte buffer.
    ///
    /// This method serializes the TXT record into a byte format, including the text content.
    /// It dynamically calculates the `rdlength` based on the length of the text.
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
        let text_bytes = self.text.as_bytes();
        match buffer.write_u16(text_bytes.len() as u16) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        for byte in text_bytes {
            match buffer.write_u8(*byte) {
                Ok(s) => s,
                Err(e) => return Err(e.into()),
            };
        }
        Ok(())
    }
}

impl DNSTXTRecord {
    /// Constructs a new `DNSTXTRecord`.
    ///
    /// This method creates a new TXT record with the specified domain name, class, TTL, and text content.
    /// It is used to convey arbitrary text information associated with a domain.
    ///
    /// # Parameters
    /// - `name`: The domain name associated with the record.
    /// - `class`: The class of the DNS record, typically `IN` for internet.
    /// - `ttl`: The time-to-live value for the record, indicating how long it should be cached.
    /// - `text`: The text content of the TXT record.
    ///
    /// # Returns
    /// A new instance of `DNSTXTRecord`.
    fn new(name: String, class: QRClass, ttl: u32, text:String) -> Self {
        DNSTXTRecord {
            preamble: DNSRecordPreamble::new(name, QRType::TXT, class, ttl, 0), // rdlength will be set later
            text,
        }
    }
}