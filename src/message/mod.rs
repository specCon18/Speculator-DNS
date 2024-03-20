mod header;
mod byte_packet_buffer;

use byte_packet_buffer::BytePacketBuffer;
use crate::records::{
    DNSRecord,
    DNSAAAARecord,
    DNSARecord,
    DNSCAARecord,
    DNSCNAMERecord,
    DNSMXRecord,
    DNSNSRecord,
    DNSPTRRecord,
    DNSSOARecord,
    DNSSRVRecord,
    DNSTXTRecord,
    DNSUNKNOWNRecord
};
use header::DNSHeaderSection;
use std::net::{
    Ipv4Addr,
    Ipv6Addr
};


#[derive(Debug, PartialEq, Eq)]
pub enum QType {
    UNKNOWN(u16),
    A,       // IPv4 address
    NS,      // Name Server
    CNAME,   // Canonical Name
    SOA,     // State of Authority
    PTR,    // Pointer Record
    MX,     // Mail Exchange
    TXT,    // Text Record
    AAAA,   // IPv6 address
    SRV,    // Service Record
    CAA,   // Certification Authority Authorization
}

impl QType {
    pub fn to_num(&self) -> u16 {
        match *self {
            QType::A => 1,       
            QType::NS => 2,      
            QType::CNAME => 5,   
            QType::SOA => 6,     
            QType::PTR => 12,    
            QType::MX => 15,     
            QType::TXT => 16,    
            QType::AAAA => 28,   
            QType::SRV => 33,    
            QType::CAA => 257,
            QType::UNKNOWN(x) => x
        }
    }

    pub fn from_num(num: u16) -> QType {
        match num {
            1 => QType::A,       
            2 => QType::NS,      
            5 => QType::CNAME,   
            6 => QType::SOA,     
            12 => QType::PTR,    
            15 => QType::MX,     
            16 => QType::TXT,    
            28 => QType::AAAA,   
            33 => QType::SRV,    
            257 => QType::CAA,
            _ => QType::UNKNOWN(num)
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum QClass {
    IN = 1,    // Internet
    CH = 3,    // CHAOS
    HS = 4,    // Hesiod
    ANY = 255, // Any class
}

impl QClass {
    pub fn from_u16(value: u16) -> Option<QClass> {
        match value {
            1 => Some(QClass::IN),
            3 => Some(QClass::CH),
            4 => Some(QClass::HS),
            255 => Some(QClass::ANY),
            _ => None,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct DNSQuestion {
    pub qname: String, // The domain name being queried
    pub qtype: QType, // The type of the query
    pub qclass: QClass, // The class of the query
}

impl DNSQuestion {
    // Constructor for creating a new DNSQuestion
    pub fn new(qname: String, qtype: QType, qclass: QClass) -> Self { DNSQuestion { qname, qtype, qclass }}
    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<(),std::io::Error> {
        buffer.read_qname(&mut self.qname)?;
        self.qtype = QType::from_num(buffer.read_u16()?); // qtype
        let _ = buffer.read_u16()?; // class

        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct DNSQuestionSection {
    questions: Vec<DNSQuestion>,
}

impl DNSQuestionSection {
    // Constructor for creating a new DNSQuestionSection
    pub fn new() -> Self { DNSQuestionSection { questions: Vec::new() }}

    // Method to add a question to the section
    pub fn add_question(&mut self, question:DNSQuestion) { self.questions.push(question); }
}

#[derive(Debug, PartialEq, Eq)]
pub struct DNSAnswerSection {
    answers: Vec<DNSRecord>,
}

impl DNSAnswerSection {
    // Constructor for creating a new DNSAnswerSection
    pub fn new() -> Self { DNSAnswerSection { answers: Vec::new() }}

    // Method to add an answer record to the section
    pub fn add_answer(&mut self, answer:DNSRecord) { self.answers.push(answer); }
}

#[derive(Debug, PartialEq, Eq)]
pub struct DNSAuthoritySection {
    records: Vec<DNSRecord>,
}

impl DNSAuthoritySection {
    // Constructor for creating a new DNSAuthoritySection
    pub fn new() -> Self { DNSAuthoritySection { records: Vec::new() }}

    // Method to add a record to the Authority section
    pub fn add_record(&mut self, record: DNSRecord) { self.records.push(record); }
}

#[derive(Debug, PartialEq, Eq)]
pub struct DNSAdditionalSection {
    records: Vec<DNSRecord>,
}

impl DNSAdditionalSection {
    // Constructor for creating a new DNSAdditionalSection
    pub fn new() -> Self { DNSAdditionalSection { records: Vec::new() }}

    // Method to add a record to the Additional section
    pub fn add_record(&mut self, record: DNSRecord) { self.records.push(record); }
}

#[derive(Debug, PartialEq, Eq)]
pub struct DNSMessage {
    pub header: DNSHeaderSection,
    pub question: DNSQuestionSection,
    pub answer: DNSAnswerSection,
    pub authority: DNSAuthoritySection,
    pub additional: DNSAdditionalSection
}

impl DNSMessage {
    // Constructor for creating a new DNSMessage
    pub fn new(header:DNSHeaderSection,question:DNSQuestionSection,answer:DNSAnswerSection,authority:DNSAuthoritySection,additional:DNSAdditionalSection) -> Self {
        DNSMessage { header, question, answer, authority, additional }
    }
    pub fn read(buffer: &mut BytePacketBuffer) -> Result<DNSRecord,std::io::Error> {
        let mut domain = String::new();
        buffer.read_qname(&mut domain)?;

        let qtype_num:u16 = buffer.read_u16()?;
        let qtype: QType = QType::from_num(qtype_num);
        let _ = buffer.read_u16()?;
        let ttl: u32 = buffer.read_u32()?;
        let data_len:u16 = buffer.read_u16()?;

        match qtype {
            QType::A => {
                let raw_addr = buffer.read_u32()?;
                let addr = Ipv4Addr::new(
                    ((raw_addr >> 24) & 0xFF) as u8,
                    ((raw_addr >> 16) & 0xFF) as u8,
                    ((raw_addr >> 8) & 0xFF) as u8,
                    ((raw_addr >> 0) & 0xFF) as u8,
                );

                Ok(DNSRecord::A(DNSARecord::new(domain, ttl, addr)))
            }
            QType::NS => {
                let mut ns_domain: String = String::new();
                buffer.read_qname(&mut ns_domain)?;

                Ok(DNSRecord::NS(DNSNSRecord::new(domain, ttl, ns_domain)))
            }
            QType::CNAME => {
                let mut canonical_name: String = String::new();
                buffer.read_qname(&mut canonical_name)?;

                Ok(DNSRecord::CNAME(DNSCNAMERecord::new(domain, ttl, canonical_name)))
            }
            QType::MX => {
                let mut exchange: String = String::new();
                buffer.read_qname(&mut exchange)?;

                let preference: u16 = buffer.read_u16()?;

                Ok(DNSRecord::MX(DNSMXRecord::new(domain, ttl, preference, exchange)))
            }
            QType::TXT => {
                let i:u16 = 0;
                let mut text: String = String::new();
                while i <= data_len {                    
                    text.push(buffer.read_byte()? as char)
                }
                Ok(DNSRecord::TXT(DNSTXTRecord::new(domain, ttl, text)))
            }
            QType::AAAA => {
                let raw_addr = buffer.read_u128()?;
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
                Ok(DNSRecord::AAAA(DNSAAAARecord::new(domain, ttl, address)))
            }
            QType::SOA => {
                //TODO: Parse Data from message
                let mname: String; // Primary name server
                let rname: String; // Responsible authority's mailbox
                let serial: u32;   // Serial number
                let refresh: u32;  // Refresh interval
                let retry: u32;    // Retry interval
                let expire: u32;   // Expiration limit
                let minimum: u32;  // Minimum TTL
                Ok(DNSRecord::SOA(DNSSOARecord::new(domain, ttl, mname, rname, serial, refresh, retry, expire, minimum)))
            }
            QType::CAA => {
                //TODO: Parse Data from message
                let flags: u8;
                let tag: String;
                let value: String;
                Ok(DNSRecord::CAA(DNSCAARecord::new(domain, ttl, flags, tag, value)))
            }
            QType::SRV => {
                //TODO: Parse Data from message
                let priority: u16;
                let weight: u16;
                let port: u16;
                let target: String;
                Ok(DNSRecord::SRV(DNSSRVRecord::new(domain, ttl, priority, weight, port, target)))
            }
            QType::PTR => {
                let mut ptrdname: String = String::new();
                buffer.read_qname(&mut ptrdname)?;
                Ok(DNSRecord::PTR(DNSPTRRecord::new(domain, ttl, ptrdname)))
            }
            QType::UNKNOWN(_) => {
                buffer.step(data_len as usize)?;
                Ok(DNSRecord::UNKNOWN(DNSUNKNOWNRecord::new(domain, ttl)))
            }
        }
    }
}
