use crate::message::{
    records::{
        DNSRecordPreamble,
        DNSRecordTrait
    },
    BytePacketBuffer,
    QRClass,
    QRType,
    DNSRecord
};
/// Represents a DNS Certification Authority Authorization (CAA) record.
///
/// A DNS CAA record allows a domain name holder to specify one or more
/// Certificate Authorities (CAs) authorized to issue certificates for that domain.
/// This can enhance the security of the domain by limiting which CAs can issue certificates.
#[derive(Debug, PartialEq, Eq)]
pub struct DNSCAARecord {
    /// Common DNS record preamble containing metadata like domain name, record type, class, and TTL.
    pub preamble: DNSRecordPreamble,
    /// Flags byte indicating issuer criticality. For now, if the value is 0, it is not critical.
    pub flags: u8,
    /// The tag indicating the property represented by this record (e.g., "issue", "issuewild", or "iodef").
    pub tag: String,
    /// The value associated with the tag, which could be a CA domain name or an email address.
    pub value: String
}

impl DNSRecordTrait for DNSCAARecord {
    /// Reads a DNS CAA record from the provided buffer and constructs a `DNSCAARecord`.
    ///
    /// # Parameters
    /// - `buffer`: A mutable reference to a `BytePacketBuffer` from which the record will be read.
    /// - `domain`: The domain name associated with the record.
    /// - `qclass`: The class of the DNS query.
    /// - `ttl`: The time-to-live value for the DNS record.
    /// - `data_len`: The length of the data in the record.
    ///
    /// # Returns
    /// A `Result` which is either:
    /// - `Ok(DNSRecord)` containing the newly constructed `DNSCAARecord`.
    /// - `Err(std::io::Error)` if there is an error reading from the buffer.
    ///
    /// # Errors
    /// This function will return an error if reading from the buffer fails at any point.
    fn read(buffer: &mut BytePacketBuffer, domain: String, qclass: QRClass, ttl: u32, data_len: u16) -> Result<DNSRecord, std::io::Error> {
        let flags: u8 = match buffer.read_u8() {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        let tag_len: u8 = match buffer.read_u8() {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        let mut i:u16 = 0;
        let mut tag: String = String::new();
        while i as u8 <= tag_len {                    
            tag.push(match buffer.read_u8() {
                Ok(s) => s,
                Err(e) => return Err(e),
            } as char);
            i += 1;
        }
        i = 0;
        let value_len:u16 = data_len - tag_len as u16;
        let value: String = String::new();
        while i <= value_len {                    
            tag.push(match buffer.read_u8() {
                Ok(s) => s,
                Err(e) => return Err(e),
            } as char);
            i += 1;
        }
        let rdata:(u8,String,String) = (flags,tag,value);
        Ok(DNSRecord::CAA(DNSCAARecord::new(domain, qclass, ttl, rdata)))
    }

    /// Writes the DNS CAA record to the given buffer.
    ///
    /// # Parameters
    /// - `buffer`: A mutable reference to a `BytePacketBuffer` where the record will be serialized.
    ///
    /// # Returns
    /// A `Result` indicating the outcome of the write operation:
    /// - `Ok(())` on success.
    /// - `Err(std::io::Error)` if an error occurs during writing.
    ///
    /// # Errors
    /// This method returns an error if writing to the buffer fails at any point.
    fn write(&self, buffer: &mut BytePacketBuffer) -> Result<(), std::io::Error> {
        let rdlength:u16 = (1 + 1 + self.tag.len() + self.value.len()).try_into().unwrap();
        
        match DNSRecordPreamble::new((*self.preamble.name).to_string(), self.preamble.rtype, self.preamble.class, self.preamble.ttl, rdlength).write(buffer) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
                
        match buffer.write_u8(self.flags) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match buffer.write_u8(self.tag.len() as u8) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        for byte in self.tag.as_bytes() {
            match buffer.write_u8(*byte) {
                Ok(s) => s,
                Err(e) => return Err(e),
            };
        }
        for byte in self.value.as_bytes() {
            match buffer.write_u8(*byte) {
                Ok(s) => s,
                Err(e) => return Err(e),
            };
        }
        Ok(())
    }
}

impl DNSCAARecord {
    /// Constructs a new `DNSCAARecord`.
    ///
    /// # Parameters
    /// - `name`: The domain name associated with the record.
    /// - `class`: The class of the DNS record, typically `IN` for internet.
    /// - `ttl`: The time-to-live value for the record, indicating how long it should be cached.
    /// - `rdata`: A tuple containing the flags, tag, and value of the CAA record.
    ///
    /// # Returns
    /// A new instance of `DNSCAARecord`.
    fn new(name: String, class: QRClass, ttl: u32, rdata:(u8,String,String)) -> Self{
        DNSCAARecord {
            preamble: DNSRecordPreamble::new(name, QRType::CAA, class, ttl, 0), // rdlength will be set later
            flags: rdata.0,
            tag: rdata.1,
            value: rdata.2,
        }
    }
}