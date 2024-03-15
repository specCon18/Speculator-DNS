
#[derive(Debug, PartialEq, Eq)]
pub enum DNSRecord {
    A(DNSARecord),
    CNAME(DNSCNAMERecord),
    NS(DNSNSRecord),
}

#[derive(Debug, PartialEq, Eq)]
pub struct DNSHeader {
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

impl DNSHeader {
    // Constructor for creating a new DNSHeader
    pub fn new(id:u16,qr:u8,opcode:u8,aa:u8,tc:u8,rd:u8,ra:u8,z:u8,ad:u8,cd:u8,rcode:u8,qdcount:u16,ancount:u16,nscount:u16,arcount:u16) -> Self {
        DNSHeader { id, qr, opcode, aa, tc, rd, ra, z, ad, cd, rcode, qdcount, ancount, nscount, arcount }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct DNSQuestion {
    pub qname: String, // The domain name being queried
    pub qtype: u16, // The type of the query
    pub qclass: u16, // The class of the query
}

impl DNSQuestion {
    // Constructor for creating a new DNSQuestion
    pub fn new(qname: String, qtype: u16, qclass: u16) -> Self { DNSQuestion { qname, qtype, qclass }}
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
pub struct DNSRecordPreamble {
    pub name: String, // The domain name the record pertains to
    pub rtype: u16, // The type of the resource record
    pub class: u16, // The class of the resource record
    pub ttl: u32, // Time to live, in seconds
    pub rdlength: u16, // Length of the RDATA field
}

impl DNSRecordPreamble {
    // Constructor for creating a new DNSRecordPreamble
    pub fn new(name: String, rtype: u16, class: u16, ttl: u32, rdlength: u16) -> Self { DNSRecordPreamble { name, rtype, class, ttl, rdlength }}
}

#[derive(Debug, PartialEq, Eq)]
pub struct DNSARecord {
    pub preamble: DNSRecordPreamble, // The common preamble for DNS records
    pub rdata: std::net::Ipv4Addr, // The IPv4 address
}

impl DNSARecord {
    // Constructor for creating a new DNSARecord
    pub fn new(name: String, ttl: u32, ipv4_address: std::net::Ipv4Addr) -> Self {
        DNSARecord {
            preamble: DNSRecordPreamble {
                name,
                rtype: 1, // The type code for an A record is 1
                class: 1, // The class for Internet is 1 (IN)
                ttl,
                rdlength: 4, // IPv4 addresses are 4 bytes in length
            },
            rdata: ipv4_address,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct DNSCNAMERecord {
    pub preamble: DNSRecordPreamble, // The common preamble for DNS records
    pub rdata: String, // The canonical domain name
}

impl DNSCNAMERecord {
    // Constructor for creating a new DNSCNAMERecord
    pub fn new(name: String, ttl: u32, canonical_name: String) -> Self {
        let rdlength = canonical_name.len() as u16; // Length of the canonical name in bytes
        DNSCNAMERecord {
            preamble: DNSRecordPreamble {
                name,
                rtype: 5, // The type code for a CNAME record is 5
                class: 1, // The class for Internet is 1 (IN)
                ttl,
                rdlength, // Set based on the length of the canonical name
            },
            rdata: canonical_name,
        }
    }
}


#[derive(Debug, PartialEq, Eq)]
pub struct DNSNSRecord {
    pub preamble: DNSRecordPreamble, // The common preamble for DNS records
    pub rdata: String, // The domain name of the authoritative name server
}

impl DNSNSRecord {
    // Constructor for creating a new DNSNSRecord
    pub fn new(name: String, ttl: u32, ns_domain: String) -> Self {
        let rdlength = ns_domain.len() as u16; // Length of the domain name in bytes
        DNSNSRecord {
            preamble: DNSRecordPreamble {
                name,
                rtype: 2, // The type code for an NS record is 2
                class: 1, // The class for Internet is 1 (IN)
                ttl,
                rdlength,
            },
            rdata: ns_domain,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct DNSMessage {
    pub header: DNSHeader,
    pub question: DNSQuestionSection,
    pub answer: DNSAnswerSection,
    pub authority: DNSAuthoritySection,
    pub additional: DNSAdditionalSection
}

impl DNSMessage {
    // Constructor for creating a new DNSMessage
    pub fn new() -> Self {
        DNSMessage {
            header: DNSHeader::new(),
            question: DNSQuestionSection::new(),
            answer: DNSAnswerSection::new(),
            authority: DNSAuthoritySection::new(),
            additional: DNSAdditionalSection::new(),
        }
    }
}


fn main() {
    // TODO: Write struct to represent binary DNS message
    // TODO: Write method to deserialized binary DNS message
    // TODO: Write method to serialize deserialzed messages
    // TODO: Write UDP Networking logic
    // TODO: Look into requirements for eDNS support
}
