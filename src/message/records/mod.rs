mod a_record;
mod aaaa_record;
mod caa_record;
mod cname_record;
mod mx_record;
mod ns_record;
mod ptr_record;
mod soa_record;
mod srv_record;
mod txt_record;
mod unknown_record;

use crate::message::{
    records::{
        a_record::DNSARecord,
        aaaa_record::DNSAAAARecord,
        caa_record::DNSCAARecord,
        cname_record::DNSCNAMERecord,
        mx_record::DNSMXRecord,
        ns_record::DNSNSRecord,
        ptr_record::DNSPTRRecord,
        soa_record::DNSSOARecord,
        srv_record::DNSSRVRecord,
        txt_record::DNSTXTRecord,
        unknown_record::DNSUNKNOWNRecord
    },
    QRType,
    QRClass,
    byte_packet_buffer::BytePacketBuffer
};

//TODO: Consider adding a macro to create these and generate this enum
/// Enumerates all supported DNS record types, including a variant for unknown record types.
#[derive(Debug, PartialEq, Eq)]
pub enum DNSRecord {
    A(DNSARecord),
    CNAME(DNSCNAMERecord),
    NS(DNSNSRecord),
    MX(DNSMXRecord),
    TXT(DNSTXTRecord),
    AAAA(DNSAAAARecord),
    SOA(DNSSOARecord),
    CAA(DNSCAARecord),
    SRV(DNSSRVRecord),
    PTR(DNSPTRRecord),
    UNKNOWN(DNSUNKNOWNRecord)
}

/// Defines the common interface for DNS record types to implement.
trait DNSRecordTrait {
    /// Reads a DNS record from a byte buffer and returns a `DNSRecord` enum variant encapsulating the record.
    fn read(buffer: &mut BytePacketBuffer, domain: String, qclass: QRClass, ttl: u32, data_len: u16) -> Result<DNSRecord, std::io::Error>;

    /// Serializes the DNS record into a byte buffer.
    fn write(&self, buffer: &mut BytePacketBuffer) -> Result<(), std::io::Error>;
}

/// Represents a DNS record, encapsulating various types of DNS records.
///
/// This enum abstracts the variety of DNS records into a single type, allowing for polymorphic
/// handling of DNS records. It supports reading from and writing to a byte packet buffer, enabling
/// DNS message serialization and deserialization.
impl DNSRecord {
    /// Reads a DNS record from a byte packet buffer, returning the appropriate `DNSRecord` variant
    /// based on the record type identified in the buffer.
    ///
    /// # Parameters
    /// - `buffer`: A mutable reference to a `BytePacketBuffer` containing the DNS record data.
    ///
    /// # Returns
    /// A `Result` which is either:
    /// - `Ok(DNSRecord)` on successful reading of the DNS record.
    /// - `Err(std::io::Error)` on failure, with an error indicating the cause.
    ///
    /// # Errors
    /// This function will return an error if there's an issue reading the record from the buffer,
    /// such as if the record type is unsupported or if there's an issue reading the buffer data.
    pub fn read(buffer: &mut BytePacketBuffer) -> Result<DNSRecord, std::io::Error> {
        let (domain, qtype, qclass, ttl, data_len) = DNSRecordPreamble::read(buffer)?;
        match qtype {
            QRType::A => DNSARecord::read(buffer, domain, qclass, ttl, data_len),
            QRType::CNAME => DNSCNAMERecord::read(buffer, domain, qclass, ttl, data_len),
            QRType::NS => DNSNSRecord::read(buffer, domain, qclass, ttl, data_len),
            QRType::MX => DNSMXRecord::read(buffer, domain, qclass, ttl, data_len),
            QRType::TXT => DNSTXTRecord::read(buffer, domain, qclass, ttl, data_len),
            QRType::AAAA => DNSAAAARecord::read(buffer, domain, qclass, ttl, data_len),
            QRType::SOA => DNSSOARecord::read(buffer, domain, qclass, ttl, data_len),
            QRType::CAA => DNSCAARecord::read(buffer, domain, qclass, ttl, data_len),
            QRType::SRV => DNSSRVRecord::read(buffer, domain, qclass, ttl, data_len),
            QRType::PTR => DNSPTRRecord::read(buffer, domain, qclass, ttl, data_len),
            QRType::UNKNOWN(0) => DNSUNKNOWNRecord::read(buffer, domain, qclass, ttl, data_len),
            _ => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Unsupported record type")),
        }
    }

    /// Writes this DNS record into a byte packet buffer.
    ///
    /// # Parameters
    /// - `buffer`: A mutable reference to a `BytePacketBuffer` where the DNS record will be written.
    ///
    /// # Returns
    /// A `Result` which is either:
    /// - `Ok(())` on successful writing of the DNS record.
    /// - `Err(std::io::Error)` on failure, with an error indicating the cause.
    ///
    /// # Errors
    /// This function will return an error if there's an issue writing the record to the buffer,
    /// such as if the record type is unsupported.
    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<(), std::io::Error> {
        // Implementation remains unchanged; adapt as needed
        match self {
            DNSRecord::A(record) => match DNSARecord::write(&record, buffer) {
                Ok(s) => s,
                Err(e) => return Err(e),
            },
            DNSRecord::CNAME(record) => match DNSCNAMERecord::write(&record, buffer) {
                Ok(s) => s,
                Err(e) => return Err(e),
            },
            DNSRecord::NS(record) => match DNSNSRecord::write(&record, buffer) {
                Ok(s) => s,
                Err(e) => return Err(e),
            },
            DNSRecord::MX(record) => match DNSMXRecord::write(&record, buffer) {
                Ok(s) => s,
                Err(e) => return Err(e),
            },
            DNSRecord::TXT(record) => match DNSTXTRecord::write(&record, buffer) {
                Ok(s) => s,
                Err(e) => return Err(e),
            },
            DNSRecord::AAAA(record) => match DNSAAAARecord::write(&record, buffer) {
                Ok(s) => s,
                Err(e) => return Err(e),
            },
            DNSRecord::SOA(record) => match DNSSOARecord::write(&record, buffer) {
                Ok(s) => s,
                Err(e) => return Err(e),
            },
            DNSRecord::CAA(record) => match DNSCAARecord::write(&record, buffer) {
                Ok(s) => s,
                Err(e) => return Err(e),
            },
            DNSRecord::SRV(record) => match DNSSRVRecord::write(&record, buffer) {
                Ok(s) => s,
                Err(e) => return Err(e),
            },
            DNSRecord::PTR(record) => match DNSPTRRecord::write(&record, buffer) {
                Ok(s) => s,
                Err(e) => return Err(e),
            },
            _ => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Unsupported record type")),
        }
        Ok(())
    }
}

/// Represents the preamble part of a DNS record.
///
/// The preamble contains the common header fields present at the start of each DNS record,
/// including the domain name, record type, class, TTL, and the data length of the record.
#[derive(Debug, PartialEq, Eq)]
pub struct DNSRecordPreamble {
    /// The domain name associated with the DNS record.
    pub name: String,
    /// The type of the DNS record.
    pub rtype: QRType,
    /// The class of the DNS record, typically `IN` for Internet.
    pub class: QRClass,
    /// The time-to-live value, specifying how long the record may be cached.
    pub ttl: u32,
    /// The length of the record data.
    pub rdlength: u16
}

impl DNSRecordPreamble {
    /// Constructs a new `DNSRecordPreamble`.
    ///
    /// # Parameters
    /// - `name`: The domain name associated with the record.
    /// - `rtype`: The DNS record type.
    /// - `class`: The class of the record, typically `IN`.
    /// - `ttl`: The time-to-live value for the record.
    /// - `rdlength`: The length of the record's data.
    ///
    /// # Returns
    /// A new instance of `DNSRecordPreamble`.
    pub fn new(name: String, rtype: QRType, class: QRClass, ttl: u32, rdlength: u16) -> Self { DNSRecordPreamble { name, rtype, class, ttl, rdlength }}

    /// Reads the preamble of a DNS record from a byte packet buffer.
    ///
    /// # Parameters
    /// - `buffer`: A mutable reference to a `BytePacketBuffer`.
    ///
    /// # Returns
    /// A `Result` which is either:
    /// - `Ok((String, QRType, QRClass, u32, u16))` on successful reading of the preamble.
    /// - `Err(std::io::Error)` on failure, with an error indicating the cause.
    ///
    /// # Errors
    /// This method returns an error if reading the preamble from the buffer fails.
    fn read(buffer: &mut BytePacketBuffer) -> Result<(String, QRType, QRClass, u32, u16), std::io::Error> {
        let mut domain: String = String::new();
        match buffer.read_qname(&mut domain) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        let qtype_num: u16 = match buffer.read_u16() {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        let qtype: QRType = QRType::from_u16(qtype_num);
        let qclass_num: u16 = 1;
        let class: QRClass = match QRClass::from_u16(qclass_num) {
            Some(s) => s,
            None => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,"raflag is not a boolean")),
        };
        let ttl: u32 = match buffer.read_u32() {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        let data_len: u16 = match buffer.read_u16() {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        Ok((domain, qtype, class, ttl, data_len))
    }

    /// Writes the preamble of this DNS record into a byte packet buffer.
    ///
    /// This method serializes the common preamble fields of a DNS record, including the domain name,
    /// record type, class, TTL, and data length, into the specified buffer. It's essential for constructing
    /// the complete DNS record for transmission.
    ///
    /// # Parameters
    /// - `buffer`: A mutable reference to a `BytePacketBuffer` where the preamble will be written.
    ///
    /// # Returns
    /// A `Result` which is either:
    /// - `Ok(())` indicating successful writing of the preamble to the buffer.
    /// - `Err(std::io::Error)` on failure, with an error detailing the cause of the failure.
    ///
    /// # Errors
    /// This method returns an error if there's an issue writing any of the preamble fields into the buffer,
    /// such as an overflow of the buffer or a problem encoding the domain name.
    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<(), std::io::Error> {
        match buffer.write_qname(&self.name) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match buffer.write_u16(self.rtype.to_u16()) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match buffer.write_u16(QRClass::to_u16(&self.class)) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match buffer.write_u32(self.ttl) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        // Note: This assumes rdlength is set correctly before calling this method.
        match buffer.write_u16(self.rdlength) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        Ok(())
    }
}