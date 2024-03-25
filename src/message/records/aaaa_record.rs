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
use std::net::Ipv6Addr;

#[derive(Debug, PartialEq, Eq)]
pub struct DNSAAAARecord {
    pub preamble: DNSRecordPreamble,
    pub address: Ipv6Addr,
}

impl DNSRecordTrait for DNSAAAARecord {
    fn read(buffer: &mut BytePacketBuffer, domain: String, qclass: QRClass, ttl: u32, _data_len: u16) -> Result<DNSRecord, std::io::Error> {
        let raw_addr = match buffer.read_u128() {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        let address:Ipv6Addr = Ipv6Addr::new(
            ((raw_addr >> 112) & 0xFFFF) as u16,
            ((raw_addr >> 96) & 0xFFFF) as u16,
            ((raw_addr >> 80) & 0xFFFF) as u16,
            ((raw_addr >> 64) & 0xFFFF) as u16,
            ((raw_addr >> 48) & 0xFFFF) as u16,
            ((raw_addr >> 32) & 0xFFFF) as u16,
            ((raw_addr >> 16) & 0xFFFF) as u16,
            ((raw_addr >> 0) & 0xFFFF) as u16,
        );
        Ok(DNSRecord::AAAA(DNSAAAARecord::new(domain,qclass, ttl, address)))
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
        match buffer.write_u16(16) {
            Ok(s) => s,
            Err(e) => return Err(e),
        }; // IPv6 address is always 16 bytes
        match buffer.write_u128(self.address.into()) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        Ok(())
    }
}

impl DNSAAAARecord {
    fn new(name: String, class: QRClass, ttl: u32, address:Ipv6Addr) -> Self {
        DNSAAAARecord {
            preamble: DNSRecordPreamble::new(name, QRType::AAAA, class, ttl, 16), // IPv6 addresses are 16 bytes
            address,
        }
    }
}