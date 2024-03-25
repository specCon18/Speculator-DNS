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
pub struct DNSNSRecord {
    pub preamble: DNSRecordPreamble, // The common preamble for DNS records
    pub rdata: String, // The domain name of the authoritative name server
}

impl DNSRecordTrait for DNSNSRecord {
    fn read(buffer: &mut BytePacketBuffer, domain: String, qclass: QRClass, ttl: u32, _data_len: u16) -> Result<DNSRecord, std::io::Error> {
        let mut ns_domain: String = String::new();
        match buffer.read_qname(&mut ns_domain) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        Ok(DNSRecord::NS(DNSNSRecord::new(domain,qclass, ttl, ns_domain)))
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
    
        let len_pos:usize = buffer.pos(); // Remember the position to write the length later
        match buffer.write_u16(0) {
            Ok(s) => s,
            Err(e) => return Err(e),
        }; // Placeholder for RDLENGTH
    
        let start_pos:usize = buffer.pos(); // Start position of RDATA
        match buffer.write_qname(&self.rdata) {
            Ok(s) => s,
            Err(e) => return Err(e),
        }; // Write the domain name of the name server
        let end_pos:usize = buffer.pos(); // End position of RDATA
    
        let rdlength:usize = end_pos - start_pos; // Calculate RDLENGTH
        match buffer.seek(len_pos) {
            Ok(s) => s,
            Err(e) => return Err(e),
        }; // Go back to write RDLENGTH
        match buffer.write_u16(rdlength as u16) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match buffer.seek(end_pos) {
            Ok(s) => s,
            Err(e) => return Err(e),
        }; // Move back to the end of the RDATA
        Ok(())
    }
}

impl DNSNSRecord {
    fn new(name: String, class: QRClass, ttl: u32, ns_domain:String) -> Self {
        DNSNSRecord {
            preamble: DNSRecordPreamble {
                name,
                rtype: QRType::NS, // The type code for an NS record is 2
                class, // The class for Internet is 1 (IN)
                ttl,
                rdlength:ns_domain.len() as u16 // Length of the domain name in bytes
            },
            rdata: ns_domain,
        }        
    }
}