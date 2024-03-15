mod header;

use super::records::DNSRecord;
use header::DNSHeaderSection;

#[derive(Debug, PartialEq, Eq)]
pub enum QType {
    A = 1,       // IPv4 address
    NS = 2,      // Name Server
    CNAME = 5,   // Canonical Name
    SOA = 6,     // State of Authority
    PTR = 12,    // Pointer Record
    MX = 15,     // Mail Exchange
    TXT = 16,    // Text Record
    AAAA = 28,   // IPv6 address
    SRV = 33,    // Service Record
    CAA = 257,   // Certification Authority Authorization
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
    pub fn serialize(){

    }
    pub fn deserialize(){
        
    }
}