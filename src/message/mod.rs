pub(crate) mod header;
mod records;
pub(crate) mod byte_packet_buffer;

use byte_packet_buffer::BytePacketBuffer;
use records::DNSRecord;
use header::DNSHeaderSection;
use std::net::Ipv4Addr;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QRType {
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

impl QRType {
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
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let as_str = match *self {
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

#[derive(Debug, Clone, Copy, PartialEq,Eq)]
pub enum QRClass {
    IN,    // Internet
    CH,    // CHAOS
    HS,    // Hesiod
    ANY, // Any class
}

impl QRClass {
    pub fn from_u16(value: u16) -> Option<QRClass> {
        match value {
            1 => Some(QRClass::IN),
            3 => Some(QRClass::CH),
            4 => Some(QRClass::HS),
            255 => Some(QRClass::ANY),
            _ => None,
        }
    }
    pub fn to_u16(value: &QRClass) -> u16 {
        match value {
            QRClass::IN => 1,
            QRClass::CH => 3,
            QRClass::HS => 4,
            QRClass::ANY => 255,
        }
    }
}

#[derive(Debug,Clone, PartialEq, Eq)]
pub struct DNSQuestion {
    pub qname: String, // The domain name being queried
    pub qtype: QRType, // The type of the query
    pub qclass: QRClass, // The class of the query
}

impl DNSQuestion {
    // Constructor for creating a new DNSQuestion
    pub fn new(qname:String,qtype:QRType,qclass:QRClass) -> Self { 
        DNSQuestion { 
            qname, 
            qtype, 
            qclass 
        }}
    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<(),std::io::Error> {
        buffer.read_qname(&mut self.qname)?;
        self.qtype = QRType::from_u16(buffer.read_u16()?); // qtype
        let _ = buffer.read_u16()?; // class

        Ok(())
    }
    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<(),std::io::Error> {
        buffer.write_qname(&self.qname)?;

        let typenum = self.qtype.to_u16();
        buffer.write_u16(typenum)?;
        buffer.write_u16(1)?;

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

#[derive(Debug, PartialEq, Eq)]
pub struct DNSPacket {
    pub header: DNSHeaderSection,
    pub question: DNSQuestionSection,
    pub answer: DNSAnswerSection,
    pub authority: DNSAuthoritySection,
    pub additional: DNSAdditionalSection
}

impl DNSPacket {
    // Constructor for creating a new DNSPacket
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
    pub fn from_buffer(buffer: &mut BytePacketBuffer) -> Result<DNSPacket,std::io::Error> {
        let mut result:DNSPacket = DNSPacket::new();
        result.header.read(buffer)?;

        for _ in 0..result.header.qdcount {
            let mut question = DNSQuestion::new("".to_string(), QRType::UNKNOWN(0),QRClass::ANY);
            question.read(buffer)?;
            result.question.add_question(question);
        }

        for _ in 0..result.header.ancount {
            let rec = DNSRecord::read(buffer)?;
            result.answer.add_answer(rec);
        }
        for _ in 0..result.header.nscount {
            let rec = DNSRecord::read(buffer)?;
            result.authority.add_record(rec);
        }
        for _ in 0..result.header.arcount {
            let rec = DNSRecord::read(buffer).unwrap();
            result.additional.add_record(rec);
        }

        Ok(result)
    }
    pub fn write(&mut self, buffer: &mut BytePacketBuffer) -> Result<(),std::io::Error> {
        self.header.qdcount = self.question.questions.len() as u16;
        self.header.ancount = self.answer.answers.len() as u16;
        self.header.nscount = self.authority.records.len() as u16;
        self.header.arcount = self.additional.records.len() as u16;

        self.header.write(buffer)?;

        for question in &self.question.questions {
            question.write(buffer)?;
        }
        for rec in &self.answer.answers {
            rec.write(buffer)?;
        }
        for rec in &self.authority.records {
            rec.write(buffer)?;
        }
        for rec in &self.additional.records {
            rec.write(buffer)?;
        }

        Ok(())
    }
    pub fn get_random_a(&self) -> Option<Ipv4Addr> {
        self.answer.answers
            .iter()
            .filter_map(|record| match record {
                DNSRecord::A(a_record) => Some(a_record.rdata),
                _ => None,
            })
            .next()
    }
    pub fn get_ns<'a>(&'a self, qname: &'a str) -> impl Iterator<Item = (&'a str, &'a str)> {
        self.authority.records
            .iter()
            .filter_map(|record| match record {
                DNSRecord::NS(ns_record) => Some((ns_record.preamble.name.as_str(), ns_record.rdata.as_str())),
                _ => None,
            })
            .filter(move |(domain, _)| qname.ends_with(*domain))
    }
    pub fn get_resolved_ns(&self, qname: &str) -> Option<Ipv4Addr> {
        self.get_ns(qname)
            .flat_map(|(_, host)| {
                self.additional.records
                    .iter()
                    .filter_map(|record| match record {
                        DNSRecord::A(a_record) if a_record.preamble.name == *host => Some(a_record.rdata),
                        _ => None,
                    })
            })
            .next()
    }
                
}
