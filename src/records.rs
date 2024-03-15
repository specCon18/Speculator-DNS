#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RType {
    A = 1,       // IPv4 address
    NS = 2,      // Name Server
    CNAME = 5,   // Canonical Name
    // TODO: Implement DNSRecord types for each of these rtypes
    MX = 15,     // Mail Exchange
    TXT = 16,    // Text Record
    AAAA = 28,   // IPv6 address
}
#[derive(Debug, Clone, Copy, PartialEq,Eq)]
pub enum RClass {
    IN = 1,    // Internet
    CH = 3,    // CHAOS
    HS = 4,    // Hesiod
}

impl RClass {
    pub fn from_u16(value: u16) -> Option<RClass> {
        match value {
            1 => Some(RClass::IN),
            3 => Some(RClass::CH),
            4 => Some(RClass::HS),
            _ => None,
        }
    }
}


#[derive(Debug, PartialEq, Eq)]
pub enum DNSRecord {
    A(DNSARecord),
    CNAME(DNSCNAMERecord),
    NS(DNSNSRecord),
}

#[derive(Debug, PartialEq, Eq)]
pub struct DNSRecordPreamble {
    pub name: String, // The domain name the record pertains to
    pub rtype: RType, // The type of the resource record
    pub class: RClass, // The class of the resource record
    pub ttl: u32, // Time to live, in seconds
    pub rdlength: u16, // Length of the RDATA field
}

impl DNSRecordPreamble {
    // Constructor for creating a new DNSRecordPreamble
    pub fn new(name: String, rtype: RType, class: RClass, ttl: u32, rdlength: u16) -> Self { DNSRecordPreamble { name, rtype, class, ttl, rdlength }}
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
                rtype: RType::A, // The type code for an A record is 1
                class: RClass::IN, // The class for Internet is 1 (IN)
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
                rtype: RType::CNAME, // The type code for a CNAME record is 5
                class: RClass::IN, // The class for Internet is 1 (IN)
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
                rtype: RType::NS, // The type code for an NS record is 2
                class: RClass::IN, // The class for Internet is 1 (IN)
                ttl,
                rdlength,
            },
            rdata: ns_domain,
        }
    }
}