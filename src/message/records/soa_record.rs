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

impl DNSRecordTrait for DNSSOARecord {
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