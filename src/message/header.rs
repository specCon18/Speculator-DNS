use super::byte_packet_buffer::BytePacketBuffer;

#[derive(Debug, PartialEq, Eq)]
pub enum OpCode {
    Query = 0,          // Standard query (QUERY)
    IQuery = 1,         // Inverse query (IQUERY, deprecated)
    Status = 2,         // Server status request (STATUS)
    Notify = 4,         // Notify (NOTIFY, RFC 1996)
    Update = 5,         // Dynamic update (UPDATE, RFC 2136)
    // Codes 6-15 are reserved for future use
}

impl OpCode {
    pub fn from_u8(value: u8) -> Option<OpCode> {
        match value {
            0 => Some(OpCode::Query),
            1 => Some(OpCode::IQuery),
            2 => Some(OpCode::Status),
            4 => Some(OpCode::Notify),
            5 => Some(OpCode::Update),
            _ => None,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum QRFlag {
    Query = 0,
    Response = 1
}

impl QRFlag {
    pub fn from_u8(value: u8) -> Option<QRFlag> {
        match value {
            0 => Some(QRFlag::Query),
            1 => Some(QRFlag::Response),
            _ => None
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum AAFlag {
    NonAuthoritative = 0,
    Authoritative = 1
}

impl AAFlag {
    pub fn from_u8(value: u8) -> Option<AAFlag> {
        match value {
            0 => Some(AAFlag::NonAuthoritative),
            1 => Some(AAFlag::Authoritative),
            _ => None
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum TCFlag {
    NonTruncated = 0,
    Truncated = 1
}

impl TCFlag {
    pub fn from_u8(value: u8) -> Option<TCFlag> {
        match value {
            0 => Some(TCFlag::NonTruncated),
            1 => Some(TCFlag::Truncated),
            _ => None
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum RDFlag {
    NonDesired = 0,
    Desired = 1
}

impl RDFlag {
    pub fn from_u8(value: u8) -> Option<RDFlag> {
        match value {
            0 => Some(RDFlag::NonDesired),
            1 => Some(RDFlag::Desired),
            _ => None
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum RAFlag {
    NonAvailable = 0,
    Available = 1
}

impl RAFlag {
    pub fn from_u8(value: u8) -> Option<RAFlag> {
        match value {
            0 => Some(RAFlag::NonAvailable),
            1 => Some(RAFlag::Available),
            _ => None
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ZFlag {
    Unused = 0,
}

impl ZFlag {
    pub fn from_u8(value: u8) -> Option<ZFlag> {
        match value {
            0 => Some(ZFlag::Unused),
            _ => None
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ADFlag {
    NonAuthenticated = 0,
    Authenticated = 1
}

impl ADFlag {
    pub fn from_u8(value: u8) -> Option<ADFlag> {
        match value {
            0 => Some(ADFlag::NonAuthenticated),
            1 => Some(ADFlag::Authenticated),
            _ => None
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum CDFlag {
    Enabled = 0,
    Disabled = 1
}

impl CDFlag {
    pub fn from_u8(value: u8) -> Option<CDFlag> {
        match value {
            0 => Some(CDFlag::Enabled),
            1 => Some(CDFlag::Disabled),
            _ => None
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum RCode {
    NoError = 0,     // No error condition
    FormErr = 1,     // Format error - The name server was unable to interpret the query.
    ServFail = 2,    // Server failure - The name server was unable to process this query due to a problem with the name server.
    NXDomain = 3,    // Non-Existent Domain - The domain name referenced in the query does not exist.
    NotImp = 4,      // Not Implemented - The name server does not support the requested kind of query.
    Refused = 5,     // Query refused - The name server refuses to perform the specified operation for policy reasons.
    YXDomain = 6,    // Name Exists when it should not
    YXRRSet = 7,     // RR Set Exists when it should not
    NXRRSet = 8,     // RR Set that should exist does not
    NotAuth = 9,     // Server Not Authoritative for zone / Not Authorized
    NotZone = 10,    // Name not contained in zone
    // Codes 11-15 are reserved for future use
    // Extended RCODEs (16-4095) are also available but not commonly used in basic implementations
}

impl RCode {
    pub fn from_u8(value: u8) -> Option<RCode> {
        match value {
            0 => Some(RCode::NoError),
            1 => Some(RCode::FormErr),
            2 => Some(RCode::ServFail),
            3 => Some(RCode::NXDomain),
            4 => Some(RCode::NotImp),
            5 => Some(RCode::Refused),
            6 => Some(RCode::YXDomain),
            7 => Some(RCode::YXRRSet),
            8 => Some(RCode::NXRRSet),
            9 => Some(RCode::NotAuth),
            10 => Some(RCode::NotZone),
            _ => None,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct DNSHeaderSection {
    pub id: u16, // Identifier: a 16-bit ID
    pub qr: QRFlag, // Query/Response Flag: 0 for query, 1 for response
    pub opcode: OpCode, // Operation Code: Specifies the kind of query
    pub aa: AAFlag, // Authoritative Answer: 0 or 1
    pub tc: TCFlag, // Truncation: Specifies if the message was truncated
    pub rd: RDFlag, // Recursion Desired: 0 or 1
    pub ra: RAFlag, // Recursion Available: Set in a response if recursion is available
    pub z: ZFlag, // Reserved for future use. Must be zero in all queries and responses
    pub ad: ADFlag, // Authenticated Data: Indicates if the data has been authenticated via DNSSEC
    pub cd: CDFlag, // Checking Disabled: Used to disable DNSSEC validation
    pub rcode: RCode, // Response Code: Status of the query
    pub qdcount: u16, // Number of questions in the Question section
    pub ancount: u16, // Number of answers in the Answer section
    pub nscount: u16, // Number of authority records in the Authority section
    pub arcount: u16, // Number of additional records in the Additional section
}

impl DNSHeaderSection {
    // Constructor for creating a new DNSHeaderSection
    pub fn new(id:u16,qr:QRFlag,opcode:OpCode,aa:AAFlag,tc:TCFlag,rd:RDFlag,ra:RAFlag,z:ZFlag,ad:ADFlag,cd:CDFlag,rcode:RCode,qdcount:u16,ancount:u16,nscount:u16,arcount:u16) -> Self {
        DNSHeaderSection { id, qr, opcode, aa, tc, rd, ra, z, ad, cd, rcode, qdcount, ancount, nscount, arcount }
    }
    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<(), std::io::Error> {
        self.id = buffer.read_u16()?;

        let flags = buffer.read_u16()?;
        let a = (flags >> 8) as u8;
        let b = (flags & 0xFF) as u8;

        // Convert boolean to u8, then use from_u8 for enum conversion
        self.rd = RDFlag::from_u8(((a & (1 << 0)) > 0) as u8).unwrap();
        self.tc = TCFlag::from_u8(((a & (1 << 1)) > 0) as u8).unwrap();
        self.aa = AAFlag::from_u8(((a & (1 << 2)) > 0) as u8).unwrap();

        // Directly extract the value for opcode, mask with 0x0F to get the correct value, then convert
        self.opcode = OpCode::from_u8((a >> 3) & 0x0F).unwrap();

        // Convert boolean to u8, then use from_u8 for enum conversion
        self.qr = QRFlag::from_u8(((a & (1 << 7)) > 0) as u8).unwrap();

        // Directly extract the value for rcode, mask with 0x0F to get the correct value, then convert
        self.rcode = RCode::from_u8(b & 0x0F).unwrap();

        // Convert boolean to u8, then use from_u8 for enum conversion for remaining flags
        self.cd = CDFlag::from_u8(((b & (1 << 4)) > 0) as u8).unwrap();
        self.ad = ADFlag::from_u8(((b & (1 << 5)) > 0) as u8).unwrap();
        self.z = ZFlag::from_u8(((b & (1 << 6)) > 0) as u8).unwrap();
        self.ra = RAFlag::from_u8(((b & (1 << 7)) > 0) as u8).unwrap();

        // Continue with buffer reading for counts
        self.qdcount = buffer.read_u16()?;
        self.ancount = buffer.read_u16()?;
        self.nscount = buffer.read_u16()?;
        self.arcount = buffer.read_u16()?;

        Ok(())
    }
}