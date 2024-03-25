use super::{DNSRecordPreamble,DNSRecordTrait,BytePacketBuffer,QRClass,QRType,DNSRecord};

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
        let serial: u32 = buffer.read_u32()?;   // Serial number
        let refresh: u32 = buffer.read_u32()?;  // Refresh interval
        let retry: u32 = buffer.read_u32()?;    // Retry interval
        let expire: u32 = buffer.read_u32()?;   // Expiration limit
        let minimum: u32 = buffer.read_u32()?;  // Minimum TTL
        let rdata:(String,String,u32,u32,u32,u32,u32) = (mname, rname, serial, refresh, retry, expire, minimum);
        Ok(DNSRecord::SOA(DNSSOARecord::new(domain, qclass, ttl, rdata)))
    }

    fn write(&self, buffer: &mut BytePacketBuffer) -> Result<(), std::io::Error> {
        buffer.write_qname(&self.preamble.name)?;
        buffer.write_u16(self.preamble.rtype.to_u16())?;
        buffer.write_u16(QRClass::to_u16(&self.preamble.class))?;
        buffer.write_u32(self.preamble.ttl)?;
        let len_pos = buffer.pos();
        buffer.write_u16(0)?; // Placeholder for length

        let start_pos = buffer.pos();
        buffer.write_qname(&self.mname)?;
        buffer.write_qname(&self.rname)?;
        buffer.write_u32(self.serial)?;
        buffer.write_u32(self.refresh)?;
        buffer.write_u32(self.retry)?;
        buffer.write_u32(self.expire)?;
        buffer.write_u32(self.minimum)?;
        let end_pos = buffer.pos();
        let rdlength = end_pos - start_pos;
        buffer.seek(len_pos)?;
        buffer.write_u16(rdlength as u16)?;
        buffer.seek(end_pos)?;
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