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

use a_record::DNSARecord;
use aaaa_record::DNSAAAARecord;
use caa_record::DNSCAARecord;
use cname_record::DNSCNAMERecord;
use mx_record::DNSMXRecord;
use ns_record::DNSNSRecord;
use ptr_record::DNSPTRRecord;
use soa_record::DNSSOARecord;
use srv_record::DNSSRVRecord;
use txt_record::DNSTXTRecord;
use unknown_record::DNSUNKNOWNRecord;
use crate::message::{QRType,QRClass,byte_packet_buffer::BytePacketBuffer};

//TODO: Consider adding a macro to create these and generate this enum
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


//TODO: Migrate records into individual sub-modules with common logic here
trait DNSRecordTrait {
    fn read(buffer: &mut BytePacketBuffer, domain: String, qclass: QRClass, ttl: u32, data_len: u16) -> Result<DNSRecord, std::io::Error> where Self: Sized;
    fn write(&self, buffer: &mut BytePacketBuffer) -> Result<(), std::io::Error>;
}


impl DNSRecord {

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

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<(), std::io::Error> {
        // Implementation remains unchanged; adapt as needed
        match self {
            DNSRecord::A(record) => DNSARecord::write(&record, buffer)?,
            DNSRecord::CNAME(record) => DNSCNAMERecord::write(&record, buffer)?,
            DNSRecord::NS(record) => DNSNSRecord::write(&record, buffer)?,
            DNSRecord::MX(record) => DNSMXRecord::write(&record, buffer)?,
            DNSRecord::TXT(record) => DNSTXTRecord::write(&record, buffer)?,
            DNSRecord::AAAA(record) => DNSAAAARecord::write(&record, buffer)?,
            DNSRecord::SOA(record) => DNSSOARecord::write(&record, buffer)?,
            DNSRecord::CAA(record) => DNSCAARecord::write(&record, buffer)?,
            DNSRecord::SRV(record) => DNSSRVRecord::write(&record, buffer)?,
            DNSRecord::PTR(record) => DNSPTRRecord::write(&record, buffer)?,
            _ => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Unsupported record type")),
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct DNSRecordPreamble {
    pub name: String, // The domain name the record pertains to
    pub rtype: QRType, // The type of the resource record
    pub class: QRClass, // The class of the resource record
    pub ttl: u32, // Time to live, in seconds
    pub rdlength: u16, // Length of the RDATA field
}

impl DNSRecordPreamble {
    // Constructor for creating a new DNSRecordPreamble
    pub fn new(name: String, rtype: QRType, class: QRClass, ttl: u32, rdlength: u16) -> Self { DNSRecordPreamble { name, rtype, class, ttl, rdlength }}

    // New helper function for reading the preamble
    fn read(buffer: &mut BytePacketBuffer) -> Result<(String, QRType, QRClass, u32, u16), std::io::Error> {
        let mut domain: String = String::new();
        buffer.read_qname(&mut domain)?;
        let qtype_num: u16 = buffer.read_u16()?;
        let qtype: QRType = QRType::from_u16(qtype_num);
        let qclass_num: u16 = 1;
        let class: QRClass = QRClass::from_u16(qclass_num).unwrap();
        let ttl: u32 = buffer.read_u32()?;
        let data_len: u16 = buffer.read_u16()?;
        Ok((domain, qtype, class, ttl, data_len))
    }

    // Method to write the common preamble parts to the buffer
    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<(), std::io::Error> {
        buffer.write_qname(&self.name)?;
        buffer.write_u16(self.rtype.to_u16())?;
        buffer.write_u16(QRClass::to_u16(&self.class))?;
        buffer.write_u32(self.ttl)?;
        // Note: This assumes rdlength is set correctly before calling this method.
        buffer.write_u16(self.rdlength)?;
        Ok(())
    }
}