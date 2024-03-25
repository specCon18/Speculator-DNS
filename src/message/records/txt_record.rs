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
pub struct DNSTXTRecord {
    pub preamble: DNSRecordPreamble,
    pub text: String
}

impl DNSRecordTrait for DNSTXTRecord {
    fn read(buffer: &mut BytePacketBuffer, domain: String, qclass: QRClass, ttl: u32, data_len: u16) -> Result<DNSRecord, std::io::Error> {
        let mut i:u16 = 0;
        let mut text: String = String::new();
        while i <= data_len {                    
            text.push(buffer.read_u8()? as char);
            i += 1;
        }
        Ok(DNSRecord::TXT(DNSTXTRecord::new(domain, qclass, ttl, text)))
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
        let text_bytes = self.text.as_bytes();
        match buffer.write_u16(text_bytes.len() as u16) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        for byte in text_bytes {
            match buffer.write_u8(*byte) {
                Ok(s) => s,
                Err(e) => return Err(e),
            };
        }
        Ok(())
    }
}

impl DNSTXTRecord {
    fn new(name: String, class: QRClass, ttl: u32, text:String) -> Self {
        DNSTXTRecord {
            preamble: DNSRecordPreamble::new(name, QRType::TXT, class, ttl, 0), // rdlength will be set later
            text,
        }
    }
}