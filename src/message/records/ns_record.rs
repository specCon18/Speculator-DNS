use super::{DNSRecordPreamble,DNSRecordTrait,BytePacketBuffer,QRClass,QRType,DNSRecord};


#[derive(Debug, PartialEq, Eq)]
pub struct DNSNSRecord {
    pub preamble: DNSRecordPreamble, // The common preamble for DNS records
    pub rdata: String, // The domain name of the authoritative name server
}

impl DNSRecordTrait for DNSNSRecord {
    fn read(buffer: &mut BytePacketBuffer, domain: String, qclass: QRClass, ttl: u32, _data_len: u16) -> Result<DNSRecord, std::io::Error> {
        let mut ns_domain: String = String::new();
        buffer.read_qname(&mut ns_domain)?;

        Ok(DNSRecord::NS(DNSNSRecord::new(domain,qclass, ttl, ns_domain)))
    }

    fn write(&self, buffer: &mut BytePacketBuffer) -> Result<(), std::io::Error> {
        buffer.write_qname(&self.preamble.name)?;
        buffer.write_u16(self.preamble.rtype.to_u16())?;
        buffer.write_u16(QRClass::to_u16(&self.preamble.class))?;
        buffer.write_u32(self.preamble.ttl)?;
    
        let len_pos = buffer.pos(); // Remember the position to write the length later
        buffer.write_u16(0)?; // Placeholder for RDLENGTH
    
        let start_pos = buffer.pos(); // Start position of RDATA
        buffer.write_qname(&self.rdata)?; // Write the domain name of the name server
        let end_pos = buffer.pos(); // End position of RDATA
    
        let rdlength = end_pos - start_pos; // Calculate RDLENGTH
        buffer.seek(len_pos)?; // Go back to write RDLENGTH
        buffer.write_u16(rdlength as u16)?;
        buffer.seek(end_pos)?; // Move back to the end of the RDATA
        Ok(())
    }
}

impl DNSNSRecord {
    fn new(name: String, class: QRClass, ttl: u32, ns_domain:String) -> Self {
        let rdlength = ns_domain.len() as u16; // Length of the domain name in bytes
        DNSNSRecord {
            preamble: DNSRecordPreamble {
                name,
                rtype: QRType::NS, // The type code for an NS record is 2
                class, // The class for Internet is 1 (IN)
                ttl,
                rdlength,
            },
            rdata: ns_domain,
        }        
    }
}