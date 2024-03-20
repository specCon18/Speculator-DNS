mod header;
pub(crate) mod byte_packet_buffer;

use byte_packet_buffer::BytePacketBuffer;
use crate::records::DNSRecord;
use header::DNSHeaderSection;



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
    pub fn new(qname:String,qtype:QType,qclass:QClass) -> Self { 
        DNSQuestion { 
            qname, 
            qtype, 
            qclass 
        }}
    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<(),std::io::Error> {
        buffer.read_qname(&mut self.qname)?;
        self.qtype = QType::from_num(buffer.read_u16()?); // qtype
        let _ = buffer.read_u16()?; // class

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
            let mut question = DNSQuestion::new("".to_string(), QType::UNKNOWN(0),QClass::ANY);
            question.read(buffer)?;
            result.question.questions.push(question);
        }

        for _ in 0..result.header.ancount {
            let rec = DNSRecord::read(buffer)?;
            result.answer.answers.push(rec);
        }
        for _ in 0..result.header.nscount {
            let rec = DNSRecord::read(buffer)?;
            result.authority.records.push(rec);
        }
        for _ in 0..result.header.arcount {
            let rec = DNSRecord::read(buffer)?;
            result.additional.records.push(rec);
        }

        Ok(result)
    }
}
