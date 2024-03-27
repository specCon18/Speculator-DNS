use crate::message::byte_packet_buffer::BytePacketBuffer;

/// Represents the DNS operation codes (OpCode) indicating the type of query being performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpCode {
    /// Standard query (QUERY)
    Query,
    /// Inverse query (IQUERY, deprecated)
    IQuery,
    /// Server status request (STATUS)
    Status,
    /// Notify (NOTIFY, RFC 1996)
    Notify,
    /// Dynamic update (UPDATE, RFC 2136)
    Update,
    // Codes 6-15 are reserved for future use
}

impl OpCode {
    /// Converts a numeric value to the corresponding OpCode.
    ///
    /// # Arguments
    ///
    /// * `value` - The numeric value representing the OpCode.
    ///
    /// # Returns
    ///
    /// Returns `Some(OpCode)` if a valid OpCode exists for the value, otherwise `None`.
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
    /// Converts an OpCode to its numeric representation.
    ///
    /// # Arguments
    ///
    /// * `value` - The OpCode to convert.
    ///
    /// # Returns
    ///
    /// Returns the numeric representation of the OpCode.
    pub fn to_u8(value:&OpCode) -> u8 {
        match value {
            OpCode::Query => 0,
            OpCode::IQuery => 1,
            OpCode::Status => 2,
            OpCode::Notify => 4,
            OpCode::Update => 5,
        }
    }
}

/// Flags indicating whether a DNS message is a query or a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QRFlag {
    Query,
    Response
}

impl QRFlag {
    /// Converts a numeric value to the corresponding QRFlag.
    ///
    /// # Arguments
    ///
    /// * `value` - The numeric value representing the QRFlag.
    ///
    /// # Returns
    ///
    /// Returns `Some(QRFlag)` if a valid QRFlag exists for the value, otherwise `None`.
    pub fn from_u8(value: u8) -> Option<QRFlag> {
        match value {
            0 => Some(QRFlag::Query),
            1 => Some(QRFlag::Response),
            _ => None
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AAFlag {
    NonAuthoritative,
    Authoritative
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TCFlag {
    NonTruncated,
    Truncated
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RDFlag {
    NonDesired,
    Desired
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RAFlag {
    NonAvailable,
    Available
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZFlag {
    Unused,
}

impl ZFlag {
    pub fn from_u8(value: u8) -> Option<ZFlag> {
        match value {
            0 => Some(ZFlag::Unused),
            _ => None
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ADFlag {
    NonAuthenticated,
    Authenticated
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CDFlag {
    Enabled,
    Disabled
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

/// Represents DNS response codes (RCode), indicating the outcome of a query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RCode {
    NoError,     // No error condition
    FormErr,     // Format error - The name server was unable to interpret the query.
    ServFail,    // Server failure - The name server was unable to process this query due to a problem with the name server.
    NXDomain,    // Non-Existent Domain - The domain name referenced in the query does not exist.
    NotImp,      // Not Implemented - The name server does not support the requested kind of query.
    Refused,     // Query refused - The name server refuses to perform the specified operation for policy reasons.
    YXDomain,    // Name Exists when it should not
    YXRRSet,     // RR Set Exists when it should not
    NXRRSet,     // RR Set that should exist does not
    NotAuth,     // Server Not Authoritative for zone / Not Authorized
    NotZone,    // Name not contained in zone
    // Codes 11-15 are reserved for future use
    // Extended RCODEs (16-4095) are also available but not commonly used in basic implementations
}

impl RCode {
    /// Converts a numeric value to the corresponding RCode.
    ///
    /// # Arguments
    ///
    /// * `value` - The numeric value representing the RCode.
    ///
    /// # Returns
    ///
    /// Returns `Some(RCode)` if a valid RCode exists for the value, otherwise `None`.
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

/// Represents the header section of a DNS message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    pub fn new() -> Self {
        let id: u16 = 0;
        let qr:QRFlag = QRFlag::Query;
        let opcode:OpCode = OpCode::Query;
        let aa:AAFlag = AAFlag::NonAuthoritative;
        let tc: TCFlag = TCFlag::NonTruncated;
        let rd: RDFlag = RDFlag::NonDesired;
        let ra: RAFlag = RAFlag::NonAvailable;
        let z: ZFlag = ZFlag::Unused;
        let ad: ADFlag = ADFlag::NonAuthenticated;
        let cd: CDFlag = CDFlag::Disabled;
        let rcode: RCode = RCode::NoError;
        let qdcount: u16 = 0;
        let ancount: u16 = 0;
        let nscount: u16 = 0;
        let arcount: u16 = 0;
        DNSHeaderSection { id, qr, opcode, aa, tc, rd, ra, z, ad, cd, rcode, qdcount, ancount, nscount, arcount }
    }
    /// Reads and populates the fields of `DNSHeaderSection` from a `BytePacketBuffer`.
    ///
    /// # Arguments
    ///
    /// * `buffer` - A mutable reference to a `BytePacketBuffer` from which to read the DNS header.
    ///
    /// # Errors
    ///
    /// Returns an `Err` if there's an issue reading from the buffer.
    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<(), std::io::Error> {
        self.id = match buffer.read_u16() {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        let flags = match buffer.read_u16() {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        let a: u8 = (flags >> 8) as u8;
        let b: u8 = (flags & 0xFF) as u8;

        // Convert boolean to u8, then use from_u8 for enum conversion
        self.rd = match RDFlag::from_u8(((a & (1 << 0)) > 0) as u8) {
            Some(s) => s,
            None => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,"rdflag is not a boolean")),
        };
        
        self.tc = match TCFlag::from_u8(((a & (1 << 1)) > 0) as u8) {
            Some(s) => s,
            None => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,"tcflag is not a boolean")),
        };

        self.aa = match AAFlag::from_u8(((a & (1 << 2)) > 0) as u8) {
            Some(s) => s,
            None => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,"aaflag is not a boolean")),
        };

        // Directly extract the value for opcode, mask with 0x0F to get the correct value, then convert
        self.opcode = match OpCode::from_u8((a >> 3) & 0x0F) {
            Some(s) => s,
            None => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,"OpCode is not one of [(QUERY),(IQUERY, deprecated),(STATUS),(NOTIFY, RFC 1996),(UPDATE, RFC 2136)]")),
        };

        // Convert boolean to u8, then use from_u8 for enum conversion
        self.qr = match QRFlag::from_u8(((a & (1 << 7)) > 0) as u8) {
            Some(s) => s,
            None => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,"qrflag is not a boolean")),
        };

        // Directly extract the value for rcode, mask with 0x0F to get the correct value, then convert
        self.rcode = match RCode::from_u8(b & 0x0F) {
            Some(s) => s,
            None => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,"rcode is not one of [NoError,FormErr,ServFail,NXDomain,NotImp,Refused,YXDomain,YXRRSet,NXRRSet,NotAuth,NotZone]")),
        };

        // Convert boolean to u8, then use from_u8 for enum conversion for remaining flags
        self.cd = match CDFlag::from_u8(((b & (1 << 4)) > 0) as u8) {
            Some(s) => s,
            None => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,"cdflag is not a boolean")),
        };
        
        self.ad = match ADFlag::from_u8(((b & (1 << 5)) > 0) as u8) {
            Some(s) => s,
            None => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,"adflag is not a boolean")),
        };
        
        self.z = match ZFlag::from_u8(((b & (1 << 6)) > 0) as u8) {
            Some(s) => s,
            None => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,"zflag is not a boolean")),
        };
        
        self.ra = match RAFlag::from_u8(((b & (1 << 7)) > 0) as u8) {
            Some(s) => s,
            None => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,"raflag is not a boolean")),
        };

        // Continue with buffer reading for counts
        self.qdcount = match buffer.read_u16() {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        
        self.ancount = match buffer.read_u16() {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        
        self.nscount = match buffer.read_u16() {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        
        self.arcount = match buffer.read_u16() {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        Ok(())
    }
    /// Writes the `DNSHeaderSection` to a `BytePacketBuffer`.
    ///
    /// # Arguments
    ///
    /// * `buffer` - A mutable reference to a `BytePacketBuffer` where the DNS header will be written.
    ///
    /// # Errors
    ///
    /// Returns an `Err` if there's an issue writing to the buffer.
    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<(),std::io::Error> {
        
        match buffer.write_u16(self.id) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        match buffer.write_u8(
                    (self.rd as u8)
                    | ((self.tc as u8) << 1) 
                    | ((self.aa as u8) << 2) 
                    | (OpCode::to_u8(&self.opcode) << 3) 
                    | ((self.qr as u8) << 7) as u8
                ) {
            Ok(s) => s,
            Err(e) => {eprintln!("{:#?}", e)}
        };

        match buffer.write_u8(
            (self.rcode as u8)
            | ((self.cd as u8) << 4)
            | ((self.ad as u8) << 5)
            | ((self.z as u8) << 6)
            | ((self.ra as u8) << 7)
        ) {
            Ok(s) => s,
            Err(e) => {eprintln!("{:#?}", e)}
        };

        match buffer.write_u16(self.qdcount) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match buffer.write_u16(self.ancount) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match buffer.write_u16(self.nscount) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match buffer.write_u16(self.arcount) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        Ok(())
    }
}