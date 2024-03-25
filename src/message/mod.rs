pub(crate) mod header;
pub(crate) mod byte_packet_buffer;
mod records;

use byte_packet_buffer::BytePacketBuffer;
use records::DNSRecord;
use header::DNSHeaderSection;
use std::net::Ipv4Addr;

/// Represents the types of DNS query records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QRType {
    /// Unknown record type
    UNKNOWN(u16),
    /// IPv4 address
    A,
    /// Name Server
    NS,
    /// Canonical Name
    CNAME,
    /// State of Authority
    SOA,
    /// Pointer Record
    PTR,
    /// Mail Exchange
    MX,
    /// Text Record
    TXT,
    /// IPv6 address
    AAAA,
    /// Service Record
    SRV,
    /// Certification Authority Authorization
    CAA,
}

impl QRType {

    /// Converts the `QRType` to its numeric representation for serialization.  
    pub fn to_u16(&self) -> u16 {
        match *self {
            QRType::A => 1,       
            QRType::NS => 2,      
            QRType::CNAME => 5,   
            QRType::SOA => 6,     
            QRType::PTR => 12,    
            QRType::MX => 15,     
            QRType::TXT => 16,    
            QRType::AAAA => 28,   
            QRType::SRV => 33,    
            QRType::CAA => 257,
            QRType::UNKNOWN(x) => x
        }
    }

    /// Converts a numeric value to the corresponding `QRType`.
    pub fn from_u16(value: u16) -> QRType {
        match value {
            1 => QRType::A,       
            2 => QRType::NS,      
            5 => QRType::CNAME,   
            6 => QRType::SOA,     
            12 => QRType::PTR,    
            15 => QRType::MX,     
            16 => QRType::TXT,    
            28 => QRType::AAAA,   
            33 => QRType::SRV,    
            257 => QRType::CAA,
            _ => QRType::UNKNOWN(value)
        }
    }
}

impl std::fmt::Display for QRType {
    /// Provides a human-readable representation of the QRType.
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let as_str: &str = match *self {
            QRType::A => "A (IPv4 address)",
            QRType::NS => "NS (Name Server)",
            QRType::CNAME => "CNAME (Canonical Name)",
            QRType::SOA => "SOA (State of Authority)",
            QRType::PTR => "PTR (Pointer Record)",
            QRType::MX => "MX (Mail Exchange)",
            QRType::TXT => "TXT (Text Record)",
            QRType::AAAA => "AAAA (IPv6 address)",
            QRType::SRV => "SRV (Service Record)",
            QRType::CAA => "CAA (Certification Authority Authorization)",
            QRType::UNKNOWN(code) => return write!(f, "UNKNOWN ({})", code),
        };
        write!(f, "{}", as_str)
    }
}

/// Represents the class of DNS query records.
#[derive(Debug, Clone, Copy, PartialEq,Eq)]
pub enum QRClass {
    /// The Internet class, most commonly used.
    IN,
    /// The CHAOS class.
    CH,
    /// The Hesiod (HS) class.
    HS,
    /// Represents any class.
    ANY,
}

impl QRClass {
    /// Converts a numeric value to the corresponding `QRClass`, if valid.
    pub fn from_u16(value: u16) -> Option<QRClass> {
        match value {
            1 => Some(QRClass::IN),
            3 => Some(QRClass::CH),
            4 => Some(QRClass::HS),
            255 => Some(QRClass::ANY),
            _ => None,
        }
    }
    /// Converts the `QRClass` to its numeric representation.
    pub fn to_u16(value: &QRClass) -> u16 {
        match value {
            QRClass::IN => 1,
            QRClass::CH => 3,
            QRClass::HS => 4,
            QRClass::ANY => 255,
        }
    }
}

/// Represents a DNS query with the domain name, query type, and query class.
#[derive(Debug,Clone, PartialEq, Eq)]
pub struct DNSQuestion {
    /// The domain name being queried.
    pub qname: String,
    /// The type of the query.
    pub qtype: QRType,
    /// The class of the query.
    pub qclass: QRClass
}

impl DNSQuestion {
    /// Constructs a new `DNSQuestion`.
    pub fn new(qname:String,qtype:QRType,qclass:QRClass) -> Self { 
        DNSQuestion { 
            qname, 
            qtype, 
            qclass 
        }}
    /// Reads and populates the fields of `DNSQuestion` from a `BytePacketBuffer`.
    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<(),std::io::Error> {
        match buffer.read_qname(&mut self.qname) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        self.qtype = QRType::from_u16(match buffer.read_u16() {
            Ok(s) => s,
            Err(e) => return Err(e),
        });
        let _ = match buffer.read_u16() {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        Ok(())
    }
    /// Writes the `DNSQuestion` to a `BytePacketBuffer`.
    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<(),std::io::Error> {
        match buffer.write_qname(&self.qname) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        let typenum: u16 = self.qtype.to_u16();
        match buffer.write_u16(typenum) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match buffer.write_u16(1) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct DNSQuestionSection {
    pub questions: Vec<DNSQuestion>,
}

impl DNSQuestionSection {
    // Constructor for creating a new DNSQuestionSection
    pub fn new() -> Self { DNSQuestionSection { questions: Vec::new() }}

    // Method to add a question to the section
    pub fn add_question(&mut self, question:DNSQuestion) { self.questions.push(question); }
}

#[derive(Debug, PartialEq, Eq)]
pub struct DNSAnswerSection {
    pub answers: Vec<DNSRecord>,
}

impl DNSAnswerSection {
    // Constructor for creating a new DNSAnswerSection
    pub fn new() -> Self { DNSAnswerSection { answers: Vec::new() }}

    // Method to add an answer record to the section
    pub fn add_answer(&mut self, answer:DNSRecord) { self.answers.push(answer); }
}

#[derive(Debug, PartialEq, Eq)]
pub struct DNSAuthoritySection {
    pub records: Vec<DNSRecord>,
}

impl DNSAuthoritySection {
    // Constructor for creating a new DNSAuthoritySection
    pub fn new() -> Self { DNSAuthoritySection { records: Vec::new() }}

    // Method to add a record to the Authority section
    pub fn add_record(&mut self, record: DNSRecord) { self.records.push(record); }
}

#[derive(Debug, PartialEq, Eq)]
pub struct DNSAdditionalSection {
    pub records: Vec<DNSRecord>,
}

impl DNSAdditionalSection {
    // Constructor for creating a new DNSAdditionalSection
    pub fn new() -> Self { DNSAdditionalSection { records: Vec::new() }}

    // Method to add a record to the Additional section
    pub fn add_record(&mut self, record: DNSRecord) { self.records.push(record); }
}

/// Represents a DNS packet including header, question, answer, authority, and additional sections.
#[derive(Debug, PartialEq, Eq)]
pub struct DNSPacket {
    pub header: DNSHeaderSection,
    pub question: DNSQuestionSection,
    pub answer: DNSAnswerSection,
    pub authority: DNSAuthoritySection,
    pub additional: DNSAdditionalSection
}

impl DNSPacket {
    /// Constructs a new `DNSPacket`.
    pub fn new() -> Self {
        let header:DNSHeaderSection = DNSHeaderSection::new();
        let question:DNSQuestionSection = DNSQuestionSection::new();
        let answer:DNSAnswerSection = DNSAnswerSection::new();
        let authority:DNSAuthoritySection = DNSAuthoritySection::new();
        let additional:DNSAdditionalSection = DNSAdditionalSection::new();
        DNSPacket { 
            header,
            question,
            answer,
            authority,
            additional
        }
    }
    /// Parses a `DNSPacket` from the given `BytePacketBuffer`.
    pub fn from_buffer(buffer: &mut BytePacketBuffer) -> Result<DNSPacket,std::io::Error> {
        let mut result:DNSPacket = DNSPacket::new();
        match result.header.read(buffer) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        for _ in 0..result.header.qdcount {
            let mut question = DNSQuestion::new("".to_string(), QRType::UNKNOWN(0),QRClass::ANY);
            match question.read(buffer) {
                Ok(s) => s,
                Err(e) => return Err(e),
            };
            result.question.add_question(question);
        }

        for _ in 0..result.header.ancount {
            let rec = match DNSRecord::read(buffer) {
                Ok(s) => s,
                Err(e) => return Err(e),
            };
            result.answer.add_answer(rec);
        }
        for _ in 0..result.header.nscount {
            let rec = match DNSRecord::read(buffer) {
                Ok(s) => s,
                Err(e) => return Err(e),
            };
            result.authority.add_record(rec);
        }
        for _ in 0..result.header.arcount {
            let rec = match DNSRecord::read(buffer) {
                Ok(s) => s,
                Err(e) => return Err(e),
            };
            result.additional.add_record(rec);
        }

        Ok(result)
    }
    
    /// Writes the `DNSPacket` to a `BytePacketBuffer`.
    pub fn write(&mut self, buffer: &mut BytePacketBuffer) -> Result<(),std::io::Error> {
        self.header.qdcount = self.question.questions.len() as u16;
        self.header.ancount = self.answer.answers.len() as u16;
        self.header.nscount = self.authority.records.len() as u16;
        self.header.arcount = self.additional.records.len() as u16;

        match self.header.write(buffer) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        for question in &self.question.questions {
            match question.write(buffer){
                Ok(s) => s,
                Err(e) => return Err(e),
            };
        }
        for rec in &self.answer.answers {
            match rec.write(buffer) {
                Ok(s) => s,
                Err(e) => return Err(e),
            };
        }
        for rec in &self.authority.records {
            match rec.write(buffer) {
                Ok(s) => s,
                Err(e) => return Err(e),
            };
        }
        for rec in &self.additional.records {
            match rec.write(buffer){
                Ok(s) => s,
                Err(e) => return Err(e),
            };
        }

        Ok(())
    }

    /// Retrieves the first IPv4 address from the answer section, if available.
    pub fn get_random_a(&self) -> Option<Ipv4Addr> {
        self.answer.answers
            .iter()
            .filter_map(|record:&DNSRecord| match record {
                DNSRecord::A(a_record) => Some(a_record.rdata),
                _ => None,
            })
            .next()
    }
    
    /// Returns an iterator over Name Server (NS) records in the authority section that match the given query name.
    pub fn get_ns<'a>(&'a self, qname: &'a str) -> impl Iterator<Item = (&'a str, &'a str)> {
        self.authority.records
            .iter()
            .filter_map(|record:&DNSRecord| match record {
                DNSRecord::NS(ns_record) => Some((ns_record.preamble.name.as_str(), ns_record.rdata.as_str())),
                _ => None,
            })
            .filter(move |(domain, _)| qname.ends_with(*domain))
    }

    /// Resolves the IP address of a name server specified in the authority section, if available in the additional section.
    pub fn get_resolved_ns(&self, qname: &str) -> Option<Ipv4Addr> {
        self.get_ns(qname)
            .flat_map(|(_, host)| {
                self.additional.records
                    .iter()
                    .filter_map(|record:&DNSRecord| match record {
                        DNSRecord::A(a_record) if a_record.preamble.name == *host => Some(a_record.rdata),
                        _ => None,
                    })
            })
            .next()
    }
                
}
