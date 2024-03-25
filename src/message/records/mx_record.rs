use super::{DNSRecordPreamble,DNSRecordTrait,BytePacketBuffer,QRClass,QRType,DNSRecord};

#[derive(Debug, PartialEq, Eq)]
pub struct DNSMXRecord {
    pub preamble: DNSRecordPreamble,
    pub preference: u16, // Preference value
    pub exchange: String, // Mail exchange domain
}

impl DNSRecordTrait for DNSMXRecord {
    fn read(buffer: &mut BytePacketBuffer, domain: String, qclass: QRClass, ttl: u32, _data_len: u16) -> Result<DNSRecord, std::io::Error> {
        let preference: u16 = buffer.read_u16()?;

        let mut exchange: String = String::new();
        buffer.read_qname(&mut exchange)?;
        
        let rdata:(u16,String) = (preference,exchange);

        Ok(DNSRecord::MX(DNSMXRecord::new(domain, qclass, ttl, rdata)))
    }

    fn write(&self, buffer: &mut BytePacketBuffer) -> Result<(), std::io::Error> {
        buffer.write_qname(&self.preamble.name)?;
        buffer.write_u16(self.preamble.rtype.to_u16())?;
        buffer.write_u16(QRClass::to_u16(&self.preamble.class))?;
        buffer.write_u32(self.preamble.ttl)?;
        let len_pos = buffer.pos();
        buffer.write_u16(0)?; // Placeholder for length

        let start_pos = buffer.pos();
        buffer.write_u16(self.preference)?;
        buffer.write_qname(&self.exchange)?;
        let end_pos = buffer.pos();
        let rdlength = end_pos - start_pos;
        buffer.seek(len_pos)?;
        buffer.write_u16(rdlength as u16)?;
        buffer.seek(end_pos)?;
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