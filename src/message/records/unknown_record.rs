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

/// Represents a DNS record of an unknown type.
///
/// This struct is used when encountering DNS records of a type not explicitly supported or recognized
/// by the DNS processing system. It allows for the parsing and storage of such records without
/// fully understanding their content, ensuring that the processing of a DNS message can continue
/// even when it contains unsupported record types.
#[derive(Debug, PartialEq, Eq)]
pub struct DNSUNKNOWNRecord {
    /// Common DNS record preamble containing metadata such as the domain name, record type, class, and TTL.
    /// For UNKNOWN records, the record type will be set to a placeholder value.
    pub preamble: DNSRecordPreamble,
    /// The raw data of the record, if any, stored as a string. For truly unknown records, this may be left as `None`.
    /// Note: In the current implementation, `rdata` is initialized as `Some("")`, indicating no data or unprocessed data.
    pub rdata:Option<String>
}

impl DNSRecordTrait for DNSUNKNOWNRecord {
    /// Attempts to read an unknown DNS record from the provided byte buffer, stepping over its data.
    ///
    /// This method does not attempt to parse the record's data due to its unknown type but ensures that
    /// the buffer's cursor is moved beyond the record's data. It effectively skips the record while
    /// preserving the ability to continue processing subsequent records.
    ///
    /// # Parameters
    /// - `buffer`: A mutable reference to a `BytePacketBuffer` from which the record's presence will be acknowledged.
    /// - `domain`: The domain name associated with the record.
    /// - `qclass`: The class of the DNS query, typically `IN` for internet.
    /// - `ttl`: The Time To Live (TTL) value for the DNS record.
    /// - `data_len`: The length of the record's data, used to skip over the record in the buffer.
    ///
    /// # Returns
    /// - `Ok(DNSRecord::UNKNOWN(..))` containing a minimal representation of the unrecognized record.
    /// - `Err(std::io::Error)` if an error occurs while stepping over the record's data in the buffer.
    fn read(buffer: &mut BytePacketBuffer, domain: String, qclass: QRClass, ttl: u32, data_len: u16) -> Result<DNSRecord, std::io::Error> {
        match buffer.step(data_len as usize) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        Ok(DNSRecord::UNKNOWN(DNSUNKNOWNRecord::new(domain,qclass, ttl,"".to_string())))
    }

    /// Stub method for writing an UNKNOWN DNS record.
    ///
    /// This method is a stub and returns an error when called, as there is no defined way to serialize
    /// an unknown record type back into a byte buffer. This reflects the practical scenario where
    /// unknown record types cannot be accurately reconstructed without understanding their structure.
    ///
    /// # Parameters
    /// - `_buffer`: Unused parameter for a `BytePacketBuffer`.
    ///
    /// # Returns
    /// - `Err(std::io::Error)` indicating failure due to the inability to write unknown record types.
    fn write(&self, _buffer: &mut BytePacketBuffer) -> Result<(), std::io::Error> {
        let e = std::io::Error::new(std::io::ErrorKind::NotFound,"Failed to write DNS Record invalid input data:");
        return Err(e);
    }
}

impl DNSUNKNOWNRecord {
    /// Constructs a new `DNSUNKNOWNRecord`.
    ///
    /// Initializes a DNSUNKNOWNRecord with given domain name, class, TTL, and optional raw data.
    /// In current usage, raw data is initialized to an empty string, but this could be adapted
    /// to carry any unprocessed or unknown data as needed.
    ///
    /// # Parameters
    /// - `name`: The domain name associated with the record.
    /// - `class`: The class of the DNS record, typically `IN` for internet.
    /// - `ttl`: The time-to-live value for the record.
    /// - `rdata`: The raw data of the unknown record, stored as a string.
    ///
    /// # Returns
    /// A new instance of `DNSUNKNOWNRecord`.
    fn new(name: String, class:QRClass, ttl: u32, rdata: String) -> Self {
        DNSUNKNOWNRecord {
            preamble:DNSRecordPreamble::new(name, QRType::UNKNOWN(0), class, ttl, 0),
            rdata: Some(rdata),
        }
    }
}