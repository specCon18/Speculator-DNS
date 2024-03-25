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
use std::net::Ipv4Addr;

#[derive(Debug, PartialEq, Eq)]
pub struct DNSARecord {
    pub preamble: DNSRecordPreamble, // The common preamble for DNS records
    pub rdata: std::net::Ipv4Addr, // The IPv4 address
}

impl DNSRecordTrait for DNSARecord {
    fn read(buffer: &mut BytePacketBuffer, domain: String, qclass: QRClass, ttl: u32, _data_len: u16) -> Result<DNSRecord, std::io::Error>{
        let raw_addr: u32 = match buffer.read_u32() {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        let addr: Ipv4Addr = Ipv4Addr::new(
            ((raw_addr >> 24) & 0xFF) as u8,
            ((raw_addr >> 16) & 0xFF) as u8,
            ((raw_addr >> 8) & 0xFF) as u8,
            ((raw_addr >> 0) & 0xFF) as u8,
        );

        Ok(DNSRecord::A(DNSARecord::new(domain,qclass,ttl,addr)))
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
        match buffer.write_u16(self.preamble.rdlength) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        
        // Write the IPv4 address
        let octets = self.rdata.octets();
        for octet in octets.iter() {
            match buffer.write_u8(*octet) {
                Ok(s) => s,
                Err(e) => return Err(e),
            };
        }
        Ok(())
    }
}

impl DNSARecord {
    fn new(name: String, class: QRClass, ttl: u32, rdata:Ipv4Addr) -> Self {
        let preamble = DNSRecordPreamble::new(name, QRType::A, class, ttl, 4);
        DNSARecord {
            preamble,
            rdata,
        }
    }
}