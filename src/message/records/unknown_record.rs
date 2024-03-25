use super::{DNSRecordPreamble,DNSRecordTrait,BytePacketBuffer,QRClass,QRType,DNSRecord};

#[derive(Debug, PartialEq, Eq)]
pub struct DNSUNKNOWNRecord {
    pub preamble: DNSRecordPreamble,
    pub rdata:Option<String>
}

impl DNSRecordTrait for DNSUNKNOWNRecord {
    
    fn read(buffer: &mut BytePacketBuffer, domain: String, qclass: QRClass, ttl: u32, data_len: u16) -> Result<DNSRecord, std::io::Error> {
        buffer.step(data_len as usize)?;
        Ok(DNSRecord::UNKNOWN(DNSUNKNOWNRecord::new(domain,qclass, ttl,"".to_string())))
    }
    
    fn write(&self, _buffer: &mut BytePacketBuffer) -> Result<(), std::io::Error> {
        let e = std::io::Error::new(std::io::ErrorKind::NotFound,format!("Failed to write DNS Record invalid input data:"));
        return Err(e);
    }
}

impl DNSUNKNOWNRecord {
    // Constructor for creating a new DNSUNKNOWNRecord
    fn new(name: String, class:QRClass, ttl: u32, rdata: String) -> Self {
        let _ = rdata;
        let preamble = DNSRecordPreamble::new(name, QRType::UNKNOWN(0), class, ttl, 0);
        DNSUNKNOWNRecord {
            preamble,
            rdata:None,
        }
    }
}