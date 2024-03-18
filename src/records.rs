#[derive(Debug, PartialEq, Eq)]
pub enum RType {
    UNKNOWN(u16),
    A,       // IPv4 address
    NS,      // Name Server
    CNAME,   // Canonical Name
    MX,     // Mail Exchange
    TXT,    // Text Record
    AAAA,   // IPv6 address
    SOA,     // State of Authority
    CAA,   // Certification Authority Authorization
    SRV,    // Service Record
    PTR,    // Pointer Record
}

impl RType {
    pub fn to_num(&self) -> u16 {
        match *self {
            RType::A => 1,       
            RType::NS => 2,      
            RType::CNAME => 5,   
            RType::SOA => 6,     
            RType::PTR => 12,    
            RType::MX => 15,     
            RType::TXT => 16,    
            RType::AAAA => 28,   
            RType::SRV => 33,    
            RType::CAA => 257,
            RType::UNKNOWN(x) => x
        }
    }

    pub fn from_num(num: u16) -> RType {
        match num {
            1 => RType::A,       
            2 => RType::NS,      
            5 => RType::CNAME,   
            6 => RType::SOA,     
            12 => RType::PTR,    
            15 => RType::MX,     
            16 => RType::TXT,    
            28 => RType::AAAA,   
            33 => RType::SRV,    
            257 => RType::CAA,
            _ => RType::UNKNOWN(num)
        }
    }
}

#[derive(Debug, PartialEq,Eq)]
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
    MX(DNSMXRecord),
    TXT(DNSTXTRecord),
    AAAA(DNSAAAARecord),
    SOA(DNSSOARecord),
    CAA(DNSCAARecord),
    SRV(DNSSRVRecord),
    PTR(DNSPTRRecord),
    UNKNOWN(DNSUNKNOWNRecord)
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
pub struct DNSUNKNOWNRecord {
    pub preamble: DNSRecordPreamble,
}

impl DNSUNKNOWNRecord {
    // Constructor for creating a new DNSARecord
    pub fn new(name: String, ttl: u32) -> Self {
        DNSUNKNOWNRecord {
            preamble: DNSRecordPreamble {
                name,
                rtype: RType::UNKNOWN(0), // The type code for an A record is 1
                class: RClass::IN, // The class for Internet is 1 (IN)
                ttl,
                rdlength: 4, // IPv4 addresses are 4 bytes in length
            },
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

#[derive(Debug, PartialEq, Eq)]
pub struct DNSMXRecord {
    pub preamble: DNSRecordPreamble,
    pub preference: u16, // Preference value
    pub exchange: String, // Mail exchange domain
}

impl DNSMXRecord {
    pub fn new(name: String, ttl: u32, preference: u16, exchange: String) -> Self {
        DNSMXRecord {
            preamble: DNSRecordPreamble::new(name, RType::MX, RClass::IN, ttl, 0), // rdlength will be set later
            preference,
            exchange,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct DNSTXTRecord {
    pub preamble: DNSRecordPreamble,
    pub text: String, // Text data
}

impl DNSTXTRecord {
    pub fn new(name: String, ttl: u32, text: String) -> Self {
        DNSTXTRecord {
            preamble: DNSRecordPreamble::new(name, RType::TXT, RClass::IN, ttl, 0), // rdlength will be set later
            text,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct DNSAAAARecord {
    pub preamble: DNSRecordPreamble,
    pub address: std::net::Ipv6Addr, // IPv6 address
}

impl DNSAAAARecord {
    pub fn new(name: String, ttl: u32, address: std::net::Ipv6Addr) -> Self {
        DNSAAAARecord {
            preamble: DNSRecordPreamble::new(name, RType::AAAA, RClass::IN, ttl, 16), // IPv6 addresses are 16 bytes
            address,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct DNSSOARecord {
    pub preamble: DNSRecordPreamble,
    pub mname: String, // Primary name server
    pub rname: String, // Responsible authority's mailbox
    pub serial: u32,   // Serial number
    pub refresh: u32,  // Refresh interval
    pub retry: u32,    // Retry interval
    pub expire: u32,   // Expiration limit
    pub minimum: u32,  // Minimum TTL
}

impl DNSSOARecord {
    pub fn new(name: String, ttl: u32, mname: String, rname: String, serial: u32, refresh: u32, retry: u32, expire: u32, minimum: u32) -> Self {
        DNSSOARecord {
            preamble: DNSRecordPreamble::new(name, RType::SOA, RClass::IN, ttl, 0), // rdlength will be set later
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct DNSCAARecord {
    pub preamble: DNSRecordPreamble,
    pub flags: u8,    // Flags
    pub tag: String,  // Tag
    pub value: String, // Value
}

impl DNSCAARecord {
    pub fn new(name: String, ttl: u32, flags: u8, tag: String, value: String) -> Self {
        DNSCAARecord {
            preamble: DNSRecordPreamble::new(name, RType::CAA, RClass::IN, ttl, 0), // rdlength will be set later
            flags,
            tag,
            value,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct DNSSRVRecord {
    pub preamble: DNSRecordPreamble,
    pub priority: u16, // Priority
    pub weight: u16,   // Weight
    pub port: u16,     // Port
    pub target: String, // Target
}

impl DNSSRVRecord {
    pub fn new(name: String, ttl: u32, priority: u16, weight: u16, port: u16, target: String) -> Self {
        DNSSRVRecord {
            preamble: DNSRecordPreamble::new(name, RType::SRV, RClass::IN, ttl, 0), // rdlength will be set later
            priority,
            weight,
            port,
            target,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct DNSPTRRecord {
    pub preamble: DNSRecordPreamble,
    pub ptrdname: String, // The domain name which the PTR points to
}

impl DNSPTRRecord {
    pub fn new(name: String, ttl: u32, ptrdname: String) -> Self {
        DNSPTRRecord {
            preamble: DNSRecordPreamble::new(name, RType::PTR, RClass::IN, ttl, 0), // rdlength will be set later
            ptrdname,
        }
    }
}
