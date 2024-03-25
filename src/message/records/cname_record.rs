use super::{DNSRecordPreamble,DNSRecordTrait,BytePacketBuffer,QRClass,QRType,DNSRecord};

#[derive(Debug, PartialEq, Eq)]
pub struct DNSCNAMERecord {
    pub preamble: DNSRecordPreamble, // The common preamble for DNS records
    pub rdata: String, // The canonical domain name
}

impl DNSRecordTrait for DNSCNAMERecord {
    fn read(buffer: &mut BytePacketBuffer, domain: String, qclass: QRClass, ttl: u32, _data_len: u16) -> Result<DNSRecord, std::io::Error> {
        let mut canonical_name: String = String::new();
        match buffer.read_qname(&mut canonical_name) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        Ok(DNSRecord::CNAME(DNSCNAMERecord::new(domain,qclass, ttl, canonical_name)))
    }

    //TODO: rewrite to step the buffer the length of the preamble then run the logic to derive rdlength then call DNSRecordPreamble::new()
    //TODO: Consider adding the rdlength parsing logic to DNSRecordPreamble::write()
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
        // Placeholder position for length
        let len_pos = buffer.pos();
        match buffer.write_u16(0) {
            Ok(s) => s,
            Err(e) => return Err(e),
        }; // Placeholder for length

        let start_pos = buffer.pos();
        match buffer.write_qname(&self.rdata) {
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

impl DNSCNAMERecord {
    fn new(name: String, class: QRClass, ttl: u32, canonical_name:String) -> Self {
        let rdlength = canonical_name.len() as u16; // Length of the canonical name in bytes
        DNSCNAMERecord {
            preamble: DNSRecordPreamble {
                name,
                rtype: QRType::CNAME, // The type code for a CNAME record is 5
                class, // The class for Internet is 1 (IN)
                ttl,
                rdlength, // Set based on the length of the canonical name
            },
            rdata: canonical_name,
        }
    }
}