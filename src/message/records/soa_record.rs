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

/// Represents a DNS SOA (Start of Authority) record.
///
/// SOA records are critical for DNS zone files. They specify foundational information about
/// the domain, including the primary name server, responsible authority's mailbox, serial number,
/// and various timing parameters. These records are vital for DNS zone transfers and for maintaining
/// the domain's integrity.
#[derive(Debug, PartialEq, Eq)]
pub struct DNSSOARecord {
    /// Common DNS record preamble containing metadata such as the domain name, record type, class, and TTL.
    pub preamble: DNSRecordPreamble,
    /// The domain name of the primary name server for the domain.
    pub mname: String,
    /// The email address of the responsible person for the domain, with '.' replacing '@'.
    pub rname: String,
    /// Serial number of the zone file, used to manage updates.
    pub serial: u32,
    /// The time interval (in seconds) before the zone should be refreshed.
    pub refresh: u32,
    /// The time interval (in seconds) between retries if the first refresh fails.
    pub retry: u32,
    /// The time interval (in seconds) that specifies when the zone data is no longer authoritative.
    pub expire: u32,
    /// The minimum TTL (in seconds) to be exported with any resource record from this zone.
    pub minimum: u32
}

impl DNSRecordTrait for DNSSOARecord {
    /// Reads a DNS SOA record from the provided byte buffer and constructs a `DNSSOARecord` instance.
    ///
    /// # Parameters
    /// - `buffer`: A mutable reference to a `BytePacketBuffer` from which the record data will be read.
    /// - `domain`: The domain name associated with the record.
    /// - `qclass`: The class of the DNS query, typically `IN` for internet.
    /// - `ttl`: The Time To Live (TTL) value for the DNS record.
    /// - `_data_len`: The length of the data section of the record, not directly used here.
    ///
    /// # Returns
    /// - `Ok(DNSRecord)` containing the newly constructed `DNSSOARecord`.
    /// - `Err(std::io::Error)` if there is an error reading from the buffer.
    fn read(buffer: &mut BytePacketBuffer, domain: String, qclass: QRClass, ttl: u32, _data_len: u16) -> Result<DNSRecord, std::io::Error> {
        
        let mut mname: String = String::new(); // Primary name server
        let _ = buffer.read_qname(&mut mname);

        let mut rname: String = String::new(); // Responsible authority's mailbox
        let _ = buffer.read_qname(&mut rname);
        
        let serial: u32 = match buffer.read_u32() {
            Ok(s) => s,
            Err(e) => return Err(e),
        };   // Serial number
        
        let refresh: u32 = match buffer.read_u32() {
            Ok(s) => s,
            Err(e) => return Err(e),
        };  // Refresh interval
        let retry: u32 = match buffer.read_u32() {
            Ok(s) => s,
            Err(e) => return Err(e),
        };    // Retry interval
        let expire: u32 = match buffer.read_u32() {
            Ok(s) => s,
            Err(e) => return Err(e),
        };   // Expiration limit
        let minimum: u32 = match buffer.read_u32() {
            Ok(s) => s,
            Err(e) => return Err(e),
        };  // Minimum TTL
        let rdata:(String,String,u32,u32,u32,u32,u32) = (mname, rname, serial, refresh, retry, expire, minimum);
        Ok(DNSRecord::SOA(DNSSOARecord::new(domain, qclass, ttl, rdata)))
    }

    //TODO: Call DNSRecordPreamble::new().write(buffer)
    /// Writes this DNS SOA record to the given byte buffer.
    ///
    /// This method serializes the SOA record into a byte format, including all fields
    /// such as the primary name server, responsible person's email, serial number, and timing parameters.
    ///
    /// # Parameters
    /// - `buffer`: A mutable reference to a `BytePacketBuffer` where the record will be serialized.
    ///
    /// # Returns
    /// - `Ok(())` on successful serialization.
    /// - `Err(std::io::Error)` if an error occurs during writing.
    fn write(&self, buffer: &mut BytePacketBuffer) -> Result<(), std::io::Error> {
        match buffer.write_qname(&self.preamble.name) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match buffer.write_u16(self.preamble.rtype.to_u16()) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match buffer.write_u16(QRClass::to_u16(&self.preamble.class)) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match buffer.write_u32(self.preamble.ttl) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        let len_pos:usize = buffer.pos();
        match buffer.write_u16(0) {
            Ok(s) => s,
            Err(e) => return Err(e),
        }; // Placeholder for length

        let start_pos:usize = buffer.pos();
        match buffer.write_qname(&self.mname) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match buffer.write_qname(&self.rname) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match buffer.write_u32(self.serial) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match buffer.write_u32(self.refresh) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match buffer.write_u32(self.retry) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match buffer.write_u32(self.expire) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match buffer.write_u32(self.minimum) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        let end_pos:usize = buffer.pos();
        let rdlength:usize = end_pos - start_pos;
        match buffer.seek(len_pos) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match buffer.write_u16(rdlength as u16) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match buffer.seek(end_pos) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        Ok(())
    }
}

impl DNSSOARecord {
    /// Constructs a new `DNSSOARecord`.
    ///
    /// This method creates a new SOA record with the specified domain name, class, TTL,
    /// primary name server, responsible person's email, serial number, and various timing parameters.
    ///
    /// # Parameters
    /// - `name`: The domain name associated with the record.
    /// - `class`: The class of the DNS record, typically `IN` for internet.
    /// - `ttl`: The time-to-live value for the record, indicating how long it should be cached.
    /// - `rdata`: A tuple containing the primary name server (mname), responsible person's email (rname),
    ///   serial number, refresh interval, retry interval, expire limit, and minimum TTL.
    ///
    /// # Returns
    /// A new instance of `DNSSOARecord`.
    fn new(name: String, class: QRClass, ttl: u32, rdata:(String,String,u32,u32,u32,u32,u32)) -> Self {
        DNSSOARecord {
            preamble: DNSRecordPreamble::new(name, QRType::SOA, class, ttl, 0), // rdlength will be set later
            mname: rdata.0,
            rname: rdata.1,
            serial: rdata.2,
            refresh: rdata.3,
            retry: rdata.4,
            expire: rdata.5,
            minimum: rdata.6,
        }
    }
}