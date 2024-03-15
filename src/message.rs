use super::records::DNSRecord;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QType {
    A = 1,       // IPv4 address
    NS = 2,      // Name Server
    CNAME = 5,   // Canonical Name
    MX = 15,     // Mail Exchange
    TXT = 16,    // Text Record
    AAAA = 28,   // IPv6 address
    // Additional query types as needed
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
pub struct DNSHeaderSection {
    pub id: u16, // Identifier: a 16-bit ID
    pub qr: u8, // Query/Response Flag: 0 for query, 1 for response
    pub opcode: u8, // Operation Code: Specifies the kind of query
    pub aa: u8, // Authoritative Answer: 0 or 1
    pub tc: u8, // Truncation: Specifies if the message was truncated
    pub rd: u8, // Recursion Desired: 0 or 1
    pub ra: u8, // Recursion Available: Set in a response if recursion is available
    pub z: u8, // Reserved for future use. Must be zero in all queries and responses
    pub ad: u8, // Authenticated Data: Indicates if the data has been authenticated via DNSSEC
    pub cd: u8, // Checking Disabled: Used to disable DNSSEC validation
    pub rcode: u8, // Response Code: Status of the query
    pub qdcount: u16, // Number of questions in the Question section
    pub ancount: u16, // Number of answers in the Answer section
    pub nscount: u16, // Number of authority records in the Authority section
    pub arcount: u16, // Number of additional records in the Additional section
}

impl DNSHeaderSection {
    // Constructor for creating a new DNSHeaderSection
    pub fn new(id:u16,qr:u8,opcode:u8,aa:u8,tc:u8,rd:u8,ra:u8,z:u8,ad:u8,cd:u8,rcode:u8,qdcount:u16,ancount:u16,nscount:u16,arcount:u16) -> Self {
        DNSHeaderSection { id, qr, opcode, aa, tc, rd, ra, z, ad, cd, rcode, qdcount, ancount, nscount, arcount }
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
    pub fn new(questions:Vec<DNSQuestion>) -> Self { DNSQuestionSection { questions }}

    // Method to add a question to the section
    pub fn add_question(&mut self, question:DNSQuestion) { self.questions.push(question); }
}

#[derive(Debug, PartialEq, Eq)]
pub struct DNSAnswerSection {
    answers: Vec<DNSRecord>,
}

impl DNSAnswerSection {
    // Constructor for creating a new DNSAnswerSection
    pub fn new(answers:Vec<DNSRecord>) -> Self {
        DNSAnswerSection { answers }
    }

    // Method to add an answer record to the section
    pub fn add_answer(&mut self, answer:DNSRecord) { self.answers.push(answer); }
}

#[derive(Debug, PartialEq, Eq)]
pub struct DNSAuthoritySection {
    records: Vec<DNSRecord>,
}

impl DNSAuthoritySection {
    // Constructor for creating a new DNSAuthoritySection
    pub fn new(records:Vec<DNSRecord>) -> Self { DNSAuthoritySection { records }}

    // Method to add a record to the Authority section
    pub fn add_record(&mut self, record: DNSRecord) { self.records.push(record); }
}

#[derive(Debug, PartialEq, Eq)]
pub struct DNSAdditionalSection {
    records: Vec<DNSRecord>,
}

impl DNSAdditionalSection {
    // Constructor for creating a new DNSAdditionalSection
    pub fn new(records:Vec<DNSRecord>) -> Self { DNSAdditionalSection { records }}

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
}