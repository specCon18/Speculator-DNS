use super::{DNSRecordPreamble,DNSRecordTrait,BytePacketBuffer,QRClass,QRType,DNSRecord};

#[derive(Debug, PartialEq, Eq)]
pub struct DNSCAARecord {
    pub preamble: DNSRecordPreamble,
    pub flags: u8,    // Flags
    pub tag: String,  // Tag
    pub value: String, // Value
}

impl DNSRecordTrait for DNSCAARecord {
    fn read(buffer: &mut BytePacketBuffer, domain: String, qclass: QRClass, ttl: u32, data_len: u16) -> Result<DNSRecord, std::io::Error> {
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
        let rdata:(u8,String,String) = (flags,tag,value);
        Ok(DNSRecord::CAA(DNSCAARecord::new(domain, qclass, ttl, rdata)))
    }

    fn write(&self, buffer: &mut BytePacketBuffer) -> Result<(), std::io::Error> {
        buffer.write_qname(&self.preamble.name)?;
        buffer.write_u16(self.preamble.rtype.to_u16())?;
        buffer.write_u16(QRClass::to_u16(&self.preamble.class))?;
        buffer.write_u32(self.preamble.ttl)?;

        let data_len = 1 + 1 + self.tag.len() + self.value.len();
        buffer.write_u16(data_len as u16)?;
                
        buffer.write_u8(self.flags)?;
        buffer.write_u8(self.tag.len() as u8)?;
        for byte in self.tag.as_bytes() {
            buffer.write_u8(*byte)?;
        }
        for byte in self.value.as_bytes() {
            buffer.write_u8(*byte)?;
        }
        Ok(())
    }
}

impl DNSCAARecord {
    fn new(name: String, class: QRClass, ttl: u32, rdata:(u8,String,String)) -> Self{
        DNSCAARecord {
            preamble: DNSRecordPreamble::new(name, QRType::CAA, class, ttl, 0), // rdlength will be set later
            flags: rdata.0,
            tag: rdata.1,
            value: rdata.2,
        }
    }
}