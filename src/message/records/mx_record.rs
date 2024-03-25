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
pub struct DNSMXRecord {
    pub preamble: DNSRecordPreamble,
    pub preference: u16, // Preference value
    pub exchange: String, // Mail exchange domain
}

impl DNSRecordTrait for DNSMXRecord {
    fn read(buffer: &mut BytePacketBuffer, domain: String, qclass: QRClass, ttl: u32, _data_len: u16) -> Result<DNSRecord, std::io::Error> {
        let preference: u16 = match buffer.read_u16() {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        let mut exchange: String = String::new();
        match buffer.read_qname(&mut exchange) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        
        let rdata:(u16,String) = (preference,exchange);

        Ok(DNSRecord::MX(DNSMXRecord::new(domain, qclass, ttl, rdata)))
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
        match buffer.write_u16(self.preference) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match buffer.write_qname(&self.exchange) {
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

impl DNSMXRecord {
    fn new(name: String, class: QRClass, ttl: u32, rdata:(u16, String)) -> Self {
        return DNSMXRecord {
            preamble: DNSRecordPreamble::new(name, QRType::MX, class, ttl, 0), // rdlength will be set later
            preference: rdata.0,
            exchange: rdata.1,
        };
    }
}