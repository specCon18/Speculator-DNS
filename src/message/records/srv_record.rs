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
pub struct DNSSRVRecord {
    pub preamble: DNSRecordPreamble,
    pub priority: u16, // Priority
    pub weight: u16,   // Weight
    pub port: u16,     // Port
    pub target: String, // Target
}

impl DNSRecordTrait for DNSSRVRecord {
    fn read(buffer: &mut BytePacketBuffer, domain: String, qclass: QRClass, ttl: u32, _data_len: u16) -> Result<DNSRecord, std::io::Error> {
        let priority: u16 = match buffer.read_u16() {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        let weight: u16 = match buffer.read_u16() {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        let port: u16 = match buffer.read_u16() {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        let mut target: String = String::new();
        match buffer.read_qname(&mut target) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        let rdata:(u16,u16,u16,String) = (priority,weight,port,target);

        Ok(DNSRecord::SRV(DNSSRVRecord::new(domain, qclass, ttl, rdata)))
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
        let len_pos = buffer.pos();
        match buffer.write_u16(0) {
            Ok(s) => s,
            Err(e) => return Err(e),
        }; // Placeholder for length

        let start_pos = buffer.pos();
        match buffer.write_u16(self.priority) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match buffer.write_u16(self.weight) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match buffer.write_u16(self.port) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match buffer.write_qname(&self.target) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        let end_pos = buffer.pos();
        let rdlength = end_pos - start_pos;
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

impl DNSSRVRecord {
    fn new(name: String, class: QRClass, ttl: u32, rdata:(u16,u16,u16,String)) -> Self {
        DNSSRVRecord {
            preamble: DNSRecordPreamble::new(name, QRType::SRV, class, ttl, 0), // rdlength will be set later
            priority: rdata.0,
            weight: rdata.1,
            port: rdata.2,
            target: rdata.3,
        }
    }
}