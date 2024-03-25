use super::{DNSRecordPreamble,DNSRecordTrait,BytePacketBuffer,QRClass,QRType,DNSRecord};

#[derive(Debug, PartialEq, Eq)]
pub struct DNSTXTRecord {
    pub preamble: DNSRecordPreamble,
    pub text: String, // Text data
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
        buffer.write_qname(&self.preamble.name)?;
        buffer.write_u16(self.preamble.rtype.to_u16())?;
        buffer.write_u16(QRClass::to_u16(&self.preamble.class))?;
        buffer.write_u32(self.preamble.ttl)?;
        let text_bytes = self.text.as_bytes();
        buffer.write_u16(text_bytes.len() as u16)?;
        for byte in text_bytes {
            buffer.write_u8(*byte)?;
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