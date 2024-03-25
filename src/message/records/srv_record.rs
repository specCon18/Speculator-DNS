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

/// Represents a DNS SRV (Service locator) record.
///
/// SRV records are used within DNS to define the location, i.e., the hostname and port, 
/// of servers for specified services. They contain the priority, weight, port, and target 
/// domain name for the service, enabling more complex service discovery mechanisms.
#[derive(Debug, PartialEq, Eq)]
pub struct DNSSRVRecord {
    /// Common DNS record preamble containing metadata such as the domain name, record type, class, and TTL.
    pub preamble: DNSRecordPreamble,
    /// Priority of the target host, lower values are preferred.
    pub priority: u16,
    /// Weight of the record. Used to distinguish between records of the same priority, higher values are preferred.
    pub weight: u16,
    /// TCP or UDP port on which the service is to be found.
    pub port: u16,
    /// The domain name of the target host.
    pub target: String
}

impl DNSRecordTrait for DNSSRVRecord {
    /// Reads a DNS SRV record from the provided byte buffer and constructs a `DNSSRVRecord` instance.
    ///
    /// # Parameters
    /// - `buffer`: A mutable reference to a `BytePacketBuffer` from which the record data will be read.
    /// - `domain`: The domain name associated with the record.
    /// - `qclass`: The class of the DNS query, typically `IN` for internet.
    /// - `ttl`: The Time To Live (TTL) value for the DNS record.
    /// - `_data_len`: The length of the data section of the record. Unused in this implementation.
    ///
    /// # Returns
    /// - `Ok(DNSRecord)` containing the newly constructed `DNSSRVRecord`.
    /// - `Err(std::io::Error)` if there is an error reading from the buffer.
    fn read(buffer: &mut BytePacketBuffer, domain: String, qclass: QRClass, ttl: u32, _data_len: u16) -> Result<DNSRecord, std::io::Error> {
        let priority: u16 = match buffer.read_u16() {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        let weight: u16 = match buffer.read_u16() {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        let port: u16 = match buffer.read_u16() {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        let mut target: String = String::new();
        match buffer.read_qname(&mut target) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        let rdata:(u16,u16,u16,String) = (priority,weight,port,target);

        Ok(DNSRecord::SRV(DNSSRVRecord::new(domain, qclass, ttl, rdata)))
    }

    //TODO: Call DNSRecordPreamble::new().write(buffer)
    /// Writes this DNS SRV record to the given byte buffer.
    ///
    /// This method serializes the SRV record into a byte format, including the priority, weight, port, 
    /// and the target domain name. It dynamically calculates the `rdlength` based on the serialized data's length.
    ///
    /// # Parameters
    /// - `buffer`: A mutable reference to a `BytePacketBuffer` where the record will be serialized.
    ///
    /// # Returns
    /// - `Ok(())` on successful serialization.
    /// - `Err(std::io::Error)` if an error occurs during writing.
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
        let len_pos = buffer.pos();
        match buffer.write_u16(0) {
            Ok(s) => s,
            Err(e) => return Err(e),
        }; // Placeholder for length

        let start_pos = buffer.pos();
        match buffer.write_u16(self.priority) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match buffer.write_u16(self.weight) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match buffer.write_u16(self.port) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match buffer.write_qname(&self.target) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        let end_pos:usize = buffer.pos();
        let rdlength:usize = end_pos - start_pos;
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

impl DNSSRVRecord {
    /// Constructs a new `DNSSRVRecord`.
    ///
    /// This method creates a new SRV record with the specified domain name, class, TTL, priority, weight, port, 
    /// and target domain name. It is used to locate servers for specified services within the domain.
    ///
    /// # Parameters
    /// - `name`: The domain name associated with the record.
    /// - `class`: The class of the DNS record, typically `IN` for internet.
    /// - `ttl`: The time-to-live value for the record, indicating how long it should be cached.
    /// - `rdata`: A tuple containing the priority, weight, port, and target domain name.
    ///
    /// # Returns
    /// A new instance of `DNSSRVRecord`.
    fn new(name: String, class: QRClass, ttl: u32, rdata:(u16,u16,u16,String)) -> Self {
        DNSSRVRecord {
            preamble: DNSRecordPreamble::new(name, QRType::SRV, class, ttl, 0), // rdlength will be set later
            priority: rdata.0,
            weight: rdata.1,
            port: rdata.2,
            target: rdata.3,
        }
    }
}