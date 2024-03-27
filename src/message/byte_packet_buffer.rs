#[derive(Debug)]
pub enum BytePacketBufferError {
    Overflow,
    UnexpectedEof,
    InvalidDomainNameFormat,
    ExceededJumpLimit,
}

/// Implements conversion from `BytePacketBufferError` to `std::io::Error`.
///
/// This implementation allows `BytePacketBufferError` types to be converted into
/// `std::io::Error`, facilitating error handling that integrates with operations
/// that may produce `std::io::Error`. This is particularly useful in contexts where
/// functions return `std::io::Error` and you are working with operations that may
/// generate `BytePacketBufferError`, enabling seamless error propagation across different
/// error types.
///
/// # Examples
///
/// This can be used in a context where a function expects a result of `Result<(), std::io::Error>`
/// but you are working with operations that return `Result<(), BytePacketBufferError>`.
/// Using the `?` operator in such a context will automatically convert `BytePacketBufferError`
/// into `std::io::Error`:
///
/// ```
/// fn some_io_operation() -> Result<(), std::io::Error> {
///     // Assuming `some_buffer_operation` returns `Result<(), BytePacketBufferError>`
///     some_buffer_operation()?;
///     Ok(())
/// }
/// ```
///
/// # Errors
///
/// This conversion handles the following `BytePacketBufferError` variants, mapping them to their
/// corresponding `std::io::ErrorKind`:
///
/// - `BytePacketBufferError::Overflow` maps to `std::io::ErrorKind::Other` with a message indicating a buffer overflow.
/// - `BytePacketBufferError::UnexpectedEof` maps to `std::io::ErrorKind::UnexpectedEof` with a message indicating an unexpected end of the buffer.
/// - `BytePacketBufferError::InvalidDomainNameFormat` maps to `std::io::ErrorKind::InvalidInput` with a message indicating an invalid domain name format.
/// - `BytePacketBufferError::ExceededJumpLimit` maps to `std::io::ErrorKind::Other` with a message indicating that the jump limit was exceeded.
impl From<BytePacketBufferError> for std::io::Error {
    fn from(err: BytePacketBufferError) -> Self {
        match err {
            BytePacketBufferError::Overflow => std::io::Error::new(std::io::ErrorKind::Other, "Buffer overflow"),
            BytePacketBufferError::UnexpectedEof => std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "Unexpected end of buffer"),
            BytePacketBufferError::InvalidDomainNameFormat => std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid domain name format"),
            BytePacketBufferError::ExceededJumpLimit => std::io::Error::new(std::io::ErrorKind::Other, "Exceeded jump limit"),
        }
    }
}

/// A buffer specifically designed to handle network packet data efficiently.
///
/// This struct provides a fixed-size buffer along with methods to manipulate
/// and navigate through the data it contains. It's particularly useful for
/// encoding and decoding packet data from protocols like DNS.
pub struct BytePacketBuffer {
    /// The fixed-size buffer where packet data is stored.
    pub buf: [u8; 512],
    /// The current position within the buffer, used for read/write operations.
    pub pos: usize,
}

impl BytePacketBuffer {
    /// Constructs a new `BytePacketBuffer`.
    ///
    /// Initializes the buffer with zeroed data and sets the position to the start of the buffer.
    pub fn new() -> BytePacketBuffer {
        BytePacketBuffer {
            buf: [0; 512],
            pos: 0,
        }
    }

    /// Returns the current position within the buffer.
    ///
    /// This position is used internally to track read/write operations.
    pub fn pos(&self) -> usize {
        self.pos
    }
    
    /// Advances the current position within the buffer by a specified number of steps.
    ///
    /// # Arguments
    ///
    /// * `steps` - The number of steps to advance the position by.
    ///
    /// # Errors
    ///
    /// Returns an `Err` if the resulting position would be outside the buffer.
    pub fn step(&mut self, steps: usize) -> Result<(),std::io::Error> {
        self.pos += steps;
        Ok(())
    }

    /// Sets the current position within the buffer to a specified value.
    ///
    /// # Arguments
    ///
    /// * `pos` - The position to set the buffer's current position to.
    ///
    /// # Errors
    ///
    /// Returns an `Err` if the specified position is outside the buffer.
    pub fn seek(&mut self, pos: usize) -> Result<(),std::io::Error> {
        self.pos = pos;
        Ok(())
    }
    
    /// Reads a single byte from the current position and advances the position by one.
    ///
    /// # Errors
    ///
    /// Returns an `Err` if attempting to read beyond the end of the buffer.
    pub fn read_u8(&mut self) -> Result<u8, BytePacketBufferError> {
        if self.pos >= self.buf.len() {
            Err(BytePacketBufferError::UnexpectedEof)
        } else {
            let res = self.buf[self.pos];
            self.pos += 1;
            Ok(res)
        }
    }
    
    /// Retrieves a single byte from the buffer at a specified position without changing the current position.
    ///
    /// # Arguments
    ///
    /// * `pos` - The position in the buffer from which to read the byte.
    ///
    /// # Errors
    ///
    /// Returns an `Err` if the specified position is outside the buffer.
    pub fn get_byte(&mut self, pos: usize) -> Result<u8,std::io::Error> {
        if pos >= 512 {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "End of buffer"));
        }
        Ok(self.buf[pos])
    }

    /// Reads a sequence of bytes starting from a specified position and for a specified length.
    ///
    /// # Arguments
    ///
    /// * `start` - The starting position in the buffer.
    /// * `len` - The number of bytes to read.
    ///
    /// # Errors
    ///
    /// Returns an `Err` if the specified range extends beyond the end of the buffer.
    pub fn get_byte_range(&mut self, start: usize, len: usize) -> Result<&[u8],std::io::Error> {
        if start + len >= 512 {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "End of buffer"));
        }
        Ok(&self.buf[start..start + len as usize])
    }

    /// Reads two bytes from the current position as a single `u16` and advances the position by two.
    ///
    /// # Errors
    ///
    /// Returns an `Err` if attempting to read beyond the end of the buffer.
    pub fn read_u16(&mut self) -> Result<u16, std::io::Error> {
        let mut result = 0u16;
        for i in (0..16).step_by(8).rev() {
            let byte = self.read_u8()? as u16;
            result |= byte << i;
        }
        Ok(result)
    }

    /// Reads four bytes from the current position as a single `u32` and advances the position by four.
    ///
    /// # Errors
    ///
    /// Returns an `Err` if attempting to read beyond the end of the buffer.
    pub fn read_u32(&mut self) -> Result<u32, std::io::Error> {
        let mut result = 0u32;
        for i in (0..32).step_by(8).rev() {
            let byte = self.read_u8()? as u32;
            result |= byte << i;
        }
        Ok(result)
    }

    /// Reads sixteen bytes from the current position as a single `u128` and advances the position by sixteen.
    ///
    /// # Errors
    ///
    /// Returns an `Err` if attempting to read beyond the end of the buffer.
    pub fn read_u128(&mut self) -> Result<u128, std::io::Error> {
        let mut result = 0u128;
        for i in (0..128).step_by(8).rev() {
            let byte = self.read_u8()? as u128;
            result |= byte << i;
        }
        Ok(result)
    }

    /// Reads a domain name (QNAME) from the buffer, handling compression according to the DNS protocol.
    ///
    /// # Arguments
    ///
    /// * `outstr` - A mutable string reference where the domain name will be appended.
    ///
    /// # Errors
    ///
    /// Returns an `Err` if an invalid domain name format is encountered or if reading beyond the buffer.
    pub fn read_qname(&mut self, outstr: &mut String) -> Result<(),std::io::Error> {

        // Since we might encounter jumps, we'll keep track of our position
        // locally as opposed to using the position within the struct. This
        // allows us to move the shared position to a point past our current
        // qname, while keeping track of our progress on the current qname
        // using this variable.
        let mut pos:usize = self.pos();

        // track whether or not we've jumped
        let mut jumped:bool = false;
        let max_jumps:i32 = 5;
        let mut jumps_performed:i32 = 0;

        // Our delimiter which we append for each label. Since we don't want a
        // dot at the beginning of the domain name we'll leave it empty for now
        // and set it to "." at the end of the first iteration.
        let mut delim:&str = "";
        loop {
            // Dns Packets are untrusted data, so we need to be paranoid. Someone
            // can craft a packet with a cycle in the jump instructions. This guards
            // against such packets.
            if jumps_performed > max_jumps {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Limit of {} jumps exceeded", max_jumps)));
            }

            // At this point, we're always at the beginning of a label. Recall
            // that labels start with a length byte.
            let len:u16 = match self.get_byte(pos) {
                Ok(s) => s as u16,
                Err(e) => return Err(e),
            };

            // If len has the two most significant bit are set, it represents a
            // jump to some other offset in the packet:
            if (len & 0xC0) == 0xC0 {
                // Update the buffer position to a point past the current
                // label. We don't need to touch it any further.
                if !jumped {
                    match self.seek(pos + 2) {
                        Ok(s) => s,
                        Err(e) => return Err(e),
                    };
                }

                // Read another byte, calculate offset and perform the jump by
                // updating our local position variable
                let b2:u16 = match self.get_byte(pos + 1) {
                    Ok(s) => s,
                    Err(e) => return Err(e),
                } as u16;
                
                let offset:u16 = (((len as u16) ^ 0xC0) << 8) | b2;
                pos = offset as usize;

                // Indicate that a jump was performed.
                jumped = true;
                jumps_performed += 1;

                continue;
            }
            // The base scenario, where we're reading a single label and
            // appending it to the output:
            else {
                // Move a single byte forward to move past the length byte.
                pos += 1;

                // Domain names are terminated by an empty label of length 0,
                // so if the length is zero we're done.
                if len == 0 {
                    break;
                }

                // Append the delimiter to our output buffer first.
                outstr.push_str(delim);

                // Extract the actual ASCII bytes for this label and append them
                // to the output buffer.
                let str_buffer = match self.get_byte_range(pos, len as usize) {
                    Ok(s) => s,
                    Err(e) => return Err(e),
                };
                outstr.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

                delim = ".";

                // Move forward the full length of the label.
                pos += len as usize;
            }
        }

        if !jumped {
            match self.seek(pos) {
                Ok(s) => s,
                Err(e) => return Err(e),
            };
        }

        Ok(())
    }

    /// Writes a single byte to the current position and advances the position by one.
    ///
    /// # Arguments
    ///
    /// * `val` - The byte value to write to the buffer.
    ///
    /// # Errors
    ///
    /// Returns an `Err` if attempting to write beyond the end of the buffer.
    pub fn write_u8(&mut self, val: u8) -> Result<(), BytePacketBufferError> {
        if self.pos >= self.buf.len() {
            Err(BytePacketBufferError::Overflow)
        } else {
            self.buf[self.pos] = val;
            self.pos += 1;
            Ok(())
        }
    }

    /// Writes two bytes and move the position two steps forward
    ///
    /// # Arguments
    ///
    /// * `val` - The byte value to write to the buffer.
    ///
    /// # Errors
    ///
    /// Returns an `Err` if attempting to write beyond the end of the buffer.
    pub fn write_u16(&mut self, val: u16) -> Result<(), std::io::Error> {
        for i in (0..16).step_by(8).rev() {
            let byte = ((val >> i) & 0xFF) as u8;
            if let Err(e) = self.write_u8(byte) {
                eprintln!("{:#?}", e);
                return Err(e.into());
            }
        }
        Ok(())
    }

    /// Writes four bytes and move the position four steps forward
    ///
    /// # Arguments
    ///
    /// * `val` - The byte value to write to the buffer.
    ///
    /// # Errors
    ///
    /// Returns an `Err` if attempting to write beyond the end of the buffer.
    pub fn write_u32(&mut self, val: u32) -> Result<(), std::io::Error> {
        for i in (0..32).step_by(8).rev() {
            let byte = ((val >> i) & 0xFF) as u8;
            if let Err(e) = self.write_u8(byte) {
                eprintln!("{:#?}", e);
                return Err(e.into());
            }
        }
        Ok(())
    }

    /// Writes sixteen bytes and move the position sixteen steps forward
    ///
    /// # Arguments
    ///
    /// * `val` - The byte value to write to the buffer.
    ///
    /// # Errors
    ///
    /// Returns an `Err` if attempting to write beyond the end of the buffer.
    pub fn write_u128(&mut self, val: u128) -> Result<(), std::io::Error> {
        for i in (0..128).step_by(8).rev() {
            let byte = ((val >> i) & 0xFF) as u8;
            if let Err(e) = self.write_u8(byte) {
                eprintln!("{:#?}", e);
                return Err(e.into());
            }
        }
        Ok(())
    }

    /// Writes a domain name to the buffer in QNAME format, handling label compression.    ///
    /// # Arguments
    ///
    /// * `val` - The byte value to write to the buffer.
    ///
    /// # Errors
    ///
    /// Returns an `Err` if attempting to write beyond the end of the buffer.
    ///
    /// This method encodes a domain name into the buffer, converting it into the QNAME format
    /// used by the DNS protocol. It handles label compression if applicable.
    ///
    /// # Arguments
    ///
    /// * `qname` - The domain name to encode into the buffer.
    ///
    /// # Errors
    ///
    /// Returns an `Err` if there is an issue with writing the domain name, such as exceeding the buffer size.
    pub fn write_qname(&mut self, qname: &str) -> Result<(), std::io::Error> {
        for label in qname.split('.').filter(|l| !l.is_empty()) {
            let len = label.len();
            if len > 0x3F { // DNS labels max length is 63
                return Err(BytePacketBufferError::InvalidDomainNameFormat.into());
            }

            self.write_u8(len as u8)?;
            for &b in label.as_bytes() {
                self.write_u8(b)?;
            }
        }
        self.write_u8(0)?; // End of QNAME
        Ok(())
    }
}