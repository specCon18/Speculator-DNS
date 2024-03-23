use crate::message::{QRType,QRClass,byte_packet_buffer::BytePacketBuffer};
use std::net::{
    Ipv4Addr,
    Ipv6Addr
};

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

impl DNSRecord {
    pub fn read(buffer: &mut BytePacketBuffer) -> Result<DNSRecord,std::io::Error> {
        let mut domain = String::new();
        buffer.read_qname(&mut domain)?;

        let qtype_num:u16 = buffer.read_u16()?;
        let qtype: QRType = QRType::from_u16(qtype_num);

        let qclass_num:u16 = 1;
        let class:QRClass = QRClass::from_u16(qclass_num).unwrap();
        
        let ttl: u32 = buffer.read_u32()?;
        let data_len:u16 = buffer.read_u16()?;

        match qtype {
            QRType::A => {
                let raw_addr = buffer.read_u32()?;
                let addr = Ipv4Addr::new(
                    ((raw_addr >> 24) & 0xFF) as u8,
                    ((raw_addr >> 16) & 0xFF) as u8,
                    ((raw_addr >> 8) & 0xFF) as u8,
                    ((raw_addr >> 0) & 0xFF) as u8,
                );

                Ok(DNSRecord::A(DNSARecord::new(domain, class, ttl, addr)))
            }
            QRType::NS => {
                let mut ns_domain: String = String::new();
                buffer.read_qname(&mut ns_domain)?;

                Ok(DNSRecord::NS(DNSNSRecord::new(domain,class, ttl, ns_domain)))
            }
            QRType::CNAME => {
                let mut canonical_name: String = String::new();
                buffer.read_qname(&mut canonical_name)?;

                Ok(DNSRecord::CNAME(DNSCNAMERecord::new(domain,class, ttl, canonical_name)))
            }
            QRType::MX => {
                let preference: u16 = buffer.read_u16()?;

                let mut exchange: String = String::new();
                buffer.read_qname(&mut exchange)?;

                Ok(DNSRecord::MX(DNSMXRecord::new(domain, class, ttl, preference, exchange)))
            }
            QRType::TXT => {
                let mut i:u16 = 0;
                let mut text: String = String::new();
                while i <= data_len {                    
                    text.push(buffer.read_u8()? as char);
                    i += 1;
                }
                Ok(DNSRecord::TXT(DNSTXTRecord::new(domain, class, ttl, text)))
            }
            QRType::AAAA => {
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
                Ok(DNSRecord::AAAA(DNSAAAARecord::new(domain,class, ttl, address)))
            }
            QRType::SOA => {
                let mut mname: String = String::new(); // Primary name server
                let _ = buffer.read_qname(&mut mname);
                let mut rname: String = String::new(); // Responsible authority's mailbox
                let _ = buffer.read_qname(&mut rname);
                let serial: u32 = buffer.read_u32()?;   // Serial number
                let refresh: u32 = buffer.read_u32()?;  // Refresh interval
                let retry: u32 = buffer.read_u32()?;    // Retry interval
                let expire: u32 = buffer.read_u32()?;   // Expiration limit
                let minimum: u32 = buffer.read_u32()?;  // Minimum TTL
                Ok(DNSRecord::SOA(DNSSOARecord::new(domain, class, ttl, mname, rname, serial, refresh, retry, expire, minimum)))
            }
            QRType::CAA => {
                let flags: u8 = buffer.read_u8()?;
                let tag_len: u8 = buffer.read_u8()?;
                let mut i:u16 = 0;
                let mut tag: String = String::new();
                while i as u8 <= tag_len {                    
                    tag.push(buffer.read_u8()? as char);
                    i += 1;
                }
                i = 0;
                let value_len = data_len - tag_len as u16;
                let value: String = String::new();
                while i <= value_len {                    
                    tag.push(buffer.read_u8()? as char);
                    i += 1;
                }
                Ok(DNSRecord::CAA(DNSCAARecord::new(domain, class, ttl, flags, tag, value)))
            }
            QRType::SRV => {
                let priority: u16 = buffer.read_u16()?;
                let weight: u16 = buffer.read_u16()?;
                let port: u16 = buffer.read_u16()?;
                let mut target: String = String::new();
                buffer.read_qname(&mut target)?;
                Ok(DNSRecord::SRV(DNSSRVRecord::new(domain, class, ttl, priority, weight, port, target)))
            }
            QRType::PTR => {
                let mut ptrdname: String = String::new();
                buffer.read_qname(&mut ptrdname)?;
                Ok(DNSRecord::PTR(DNSPTRRecord::new(domain,class, ttl, ptrdname)))
            }
            QRType::UNKNOWN(_) => {
                buffer.step(data_len as usize)?;
                Ok(DNSRecord::UNKNOWN(DNSUNKNOWNRecord::new(domain,class, ttl)))
            }
        }
    }
    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<(), std::io::Error> {
        match self {
            DNSRecord::A(record) => {
                buffer.write_qname(&record.preamble.name)?;
                buffer.write_u16(record.preamble.rtype.to_u16())?;
                buffer.write_u16(QRClass::to_u16(&record.preamble.class))?;
                buffer.write_u32(record.preamble.ttl)?;
                buffer.write_u16(record.preamble.rdlength)?;
                
                // Write the IPv4 address
                let octets = record.rdata.octets();
                for octet in octets.iter() {
                    buffer.write_u8(*octet)?;
                }
            },
            DNSRecord::CNAME(record) => {
                buffer.write_qname(&record.preamble.name)?;
                buffer.write_u16(record.preamble.rtype.to_u16())?;
                buffer.write_u16(QRClass::to_u16(&record.preamble.class))?;
                buffer.write_u32(record.preamble.ttl)?;
                // Placeholder position for length
                let len_pos = buffer.pos();
                buffer.write_u16(0)?; // Placeholder for length

                let start_pos = buffer.pos();
                buffer.write_qname(&record.rdata)?;
                let end_pos = buffer.pos();
                let rdlength = end_pos - start_pos;
                buffer.seek(len_pos)?;
                buffer.write_u16(rdlength as u16)?;
                buffer.seek(end_pos)?;
            },
            DNSRecord::MX(record) => {
                buffer.write_qname(&record.preamble.name)?;
                buffer.write_u16(record.preamble.rtype.to_u16())?;
                buffer.write_u16(QRClass::to_u16(&record.preamble.class))?;
                buffer.write_u32(record.preamble.ttl)?;
                let len_pos = buffer.pos();
                buffer.write_u16(0)?; // Placeholder for length

                let start_pos = buffer.pos();
                buffer.write_u16(record.preference)?;
                buffer.write_qname(&record.exchange)?;
                let end_pos = buffer.pos();
                let rdlength = end_pos - start_pos;
                buffer.seek(len_pos)?;
                buffer.write_u16(rdlength as u16)?;
                buffer.seek(end_pos)?;
            },
            DNSRecord::TXT(record) => {
                buffer.write_qname(&record.preamble.name)?;
                buffer.write_u16(record.preamble.rtype.to_u16())?;
                buffer.write_u16(QRClass::to_u16(&record.preamble.class))?;
                buffer.write_u32(record.preamble.ttl)?;
                let text_bytes = record.text.as_bytes();
                buffer.write_u16(text_bytes.len() as u16)?;
                for byte in text_bytes {
                    buffer.write_u8(*byte)?;
                }
            },
            DNSRecord::AAAA(record) => {
                buffer.write_qname(&record.preamble.name)?;
                buffer.write_u16(record.preamble.rtype.to_u16())?;
                buffer.write_u16(QRClass::to_u16(&record.preamble.class))?;
                buffer.write_u32(record.preamble.ttl)?;
                buffer.write_u16(16)?; // IPv6 address is always 16 bytes
                buffer.write_u128(record.address.into())?;
            },
            DNSRecord::SOA(record) => {
                buffer.write_qname(&record.preamble.name)?;
                buffer.write_u16(record.preamble.rtype.to_u16())?;
                buffer.write_u16(QRClass::to_u16(&record.preamble.class))?;
                buffer.write_u32(record.preamble.ttl)?;
                let len_pos = buffer.pos();
                buffer.write_u16(0)?; // Placeholder for length

                let start_pos = buffer.pos();
                buffer.write_qname(&record.mname)?;
                buffer.write_qname(&record.rname)?;
                buffer.write_u32(record.serial)?;
                buffer.write_u32(record.refresh)?;
                buffer.write_u32(record.retry)?;
                buffer.write_u32(record.expire)?;
                buffer.write_u32(record.minimum)?;
                let end_pos = buffer.pos();
                let rdlength = end_pos - start_pos;
                buffer.seek(len_pos)?;
                buffer.write_u16(rdlength as u16)?;
                buffer.seek(end_pos)?;
            },
            DNSRecord::SRV(record) => {
                buffer.write_qname(&record.preamble.name)?;
                buffer.write_u16(record.preamble.rtype.to_u16())?;
                buffer.write_u16(QRClass::to_u16(&record.preamble.class))?;
                buffer.write_u32(record.preamble.ttl)?;
                let len_pos = buffer.pos();
                buffer.write_u16(0)?; // Placeholder for length

                let start_pos = buffer.pos();
                buffer.write_u16(record.priority)?;
                buffer.write_u16(record.weight)?;
                buffer.write_u16(record.port)?;
                buffer.write_qname(&record.target)?;
                let end_pos = buffer.pos();
                let rdlength = end_pos - start_pos;
                buffer.seek(len_pos)?;
                buffer.write_u16(rdlength as u16)?;
                buffer.seek(end_pos)?;
            },
            DNSRecord::CAA(record) => {
                buffer.write_qname(&record.preamble.name)?;
                buffer.write_u16(record.preamble.rtype.to_u16())?;
                buffer.write_u16(QRClass::to_u16(&record.preamble.class))?;
                buffer.write_u32(record.preamble.ttl)?;
                // Calculate the length of the CAA record data.
                // Flags (1 byte) + Tag length (1 byte) + Tag + Value
                let data_len = 1 + 1 + record.tag.len() + record.value.len();
                buffer.write_u16(data_len as u16)?;
                        
                buffer.write_u8(record.flags)?;
                buffer.write_u8(record.tag.len() as u8)?;
                for byte in record.tag.as_bytes() {
                    buffer.write_u8(*byte)?;
                }
                for byte in record.value.as_bytes() {
                    buffer.write_u8(*byte)?;
                }
            },
            DNSRecord::PTR(record) => {
                buffer.write_qname(&record.preamble.name)?;
                buffer.write_u16(record.preamble.rtype.to_u16())?;
                buffer.write_u16(QRClass::to_u16(&record.preamble.class))?;
                buffer.write_u32(record.preamble.ttl)?;
                let len_pos = buffer.pos();
                buffer.write_u16(0)?; // Placeholder for length

                let start_pos = buffer.pos();
                buffer.write_qname(&record.ptrdname)?;
                let end_pos = buffer.pos();
                let rdlength = end_pos - start_pos;
                buffer.seek(len_pos)?;
                buffer.write_u16(rdlength as u16)?;
                buffer.seek(end_pos)?;
            },
            // Handle other record types similarly...
            _ => return Err(std::io::Error::new(std::io::ErrorKind::Other, "Unsupported record type")),
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
}

#[derive(Debug, PartialEq, Eq)]
pub struct DNSARecord {
    pub preamble: DNSRecordPreamble, // The common preamble for DNS records
    pub rdata: std::net::Ipv4Addr, // The IPv4 address
}

impl DNSARecord {
    // Constructor for creating a new DNSARecord
    pub fn new(name: String, class:QRClass, ttl: u32, ipv4_address: std::net::Ipv4Addr) -> Self {
        DNSARecord {
            preamble: DNSRecordPreamble {
                name,
                rtype: QRType::A, // The type code for an A record is 1
                class, // The class for Internet is 1 (IN)
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
    pub fn new(name: String, class:QRClass, ttl: u32) -> Self {
        DNSUNKNOWNRecord {
            preamble: DNSRecordPreamble {
                name,
                rtype: QRType::UNKNOWN(0), // The type code for an A record is 1
                class, // The class for Internet is 1 (IN)
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
    pub fn new(name: String, class:QRClass, ttl: u32, canonical_name: String) -> Self {
        let rdlength = canonical_name.len() as u16; // Length of the canonical name in bytes
        DNSCNAMERecord {
            preamble: DNSRecordPreamble {
                name,
                rtype: QRType::CNAME, // The type code for a CNAME record is 5
                class, // The class for Internet is 1 (IN)
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
    pub fn new(name: String,class: QRClass, ttl: u32, ns_domain: String) -> Self {
        let rdlength = ns_domain.len() as u16; // Length of the domain name in bytes
        DNSNSRecord {
            preamble: DNSRecordPreamble {
                name,
                rtype: QRType::NS, // The type code for an NS record is 2
                class, // The class for Internet is 1 (IN)
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
    pub fn new(name: String, class:QRClass, ttl: u32, preference: u16, exchange: String) -> Self {
        DNSMXRecord {
            preamble: DNSRecordPreamble::new(name, QRType::MX, class, ttl, 0), // rdlength will be set later
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
    pub fn new(name: String, class:QRClass, ttl: u32, text: String) -> Self {
        DNSTXTRecord {
            preamble: DNSRecordPreamble::new(name, QRType::TXT, class, ttl, 0), // rdlength will be set later
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
    pub fn new(name: String, class:QRClass, ttl: u32, address: std::net::Ipv6Addr) -> Self {
        DNSAAAARecord {
            preamble: DNSRecordPreamble::new(name, QRType::AAAA, class, ttl, 16), // IPv6 addresses are 16 bytes
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
    pub fn new(name: String, class:QRClass, ttl: u32, mname: String, rname: String, serial: u32, refresh: u32, retry: u32, expire: u32, minimum: u32) -> Self {
        DNSSOARecord {
            preamble: DNSRecordPreamble::new(name, QRType::SOA, class, ttl, 0), // rdlength will be set later
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
    pub fn new(name: String, class:QRClass, ttl: u32, flags: u8, tag: String, value: String) -> Self {
        DNSCAARecord {
            preamble: DNSRecordPreamble::new(name, QRType::CAA, class, ttl, 0), // rdlength will be set later
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
    pub fn new(name: String, class:QRClass, ttl: u32, priority: u16, weight: u16, port: u16, target: String) -> Self {
        DNSSRVRecord {
            preamble: DNSRecordPreamble::new(name, QRType::SRV, class, ttl, 0), // rdlength will be set later
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
    pub fn new(name: String, class:QRClass, ttl: u32, ptrdname: String) -> Self {
        DNSPTRRecord {
            preamble: DNSRecordPreamble::new(name, QRType::PTR, class, ttl, 0), // rdlength will be set later
            ptrdname,
        }
    }
}
