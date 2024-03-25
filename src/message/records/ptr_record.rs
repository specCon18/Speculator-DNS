use super::{DNSRecordPreamble,DNSRecordTrait,BytePacketBuffer,QRClass,QRType,DNSRecord};

#[derive(Debug, PartialEq, Eq)]
pub struct DNSPTRRecord {
    pub preamble: DNSRecordPreamble,
    pub ptrdname: String, // The domain name which the PTR points to
}

impl DNSRecordTrait for DNSPTRRecord {
    fn read(buffer: &mut BytePacketBuffer, domain: String, qclass: QRClass, ttl: u32, _data_len: u16) -> Result<DNSRecord, std::io::Error> {
        let mut ptrdname: String = String::new();
        buffer.read_qname(&mut ptrdname)?;
        Ok(DNSRecord::PTR(DNSPTRRecord::new(domain,qclass, ttl, ptrdname)))
    }

    fn write(&self, buffer: &mut BytePacketBuffer) -> Result<(), std::io::Error> {
        buffer.write_qname(&self.preamble.name)?;
        buffer.write_u16(self.preamble.rtype.to_u16())?;
        buffer.write_u16(QRClass::to_u16(&self.preamble.class))?;
        buffer.write_u32(self.preamble.ttl)?;
        let len_pos = buffer.pos();
        buffer.write_u16(0)?; // Placeholder for length

        let start_pos = buffer.pos();
        buffer.write_qname(&self.ptrdname)?;
        let end_pos = buffer.pos();
        let rdlength = end_pos - start_pos;
        buffer.seek(len_pos)?;
        buffer.write_u16(rdlength as u16)?;
        buffer.seek(end_pos)?;
        Ok(())
    }
}

impl DNSPTRRecord {
    fn new(name: String, class: QRClass, ttl: u32, ptrdname:String) -> Self {
        DNSPTRRecord {
            preamble: DNSRecordPreamble::new(name, QRType::PTR, class, ttl, 0), // rdlength will be set later
            ptrdname,
        }
    }
}