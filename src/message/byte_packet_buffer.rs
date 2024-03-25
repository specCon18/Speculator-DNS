pub struct BytePacketBuffer {
    pub buf: [u8; 512],
    pub pos: usize,
}

impl BytePacketBuffer {
    /// This gives us a fresh buffer for holding the packet contents, and a
    /// field for keeping track of where we are.
    pub fn new() -> BytePacketBuffer {
        BytePacketBuffer {
            buf: [0; 512],
            pos: 0,
        }
    }

    /// Get the current position within buffer
    pub fn pos(&self) -> usize {
        self.pos
    }
    
    /// Step the buffer position forward a specific number of steps
    pub fn step(&mut self, steps: usize) -> Result<(),std::io::Error> {
        self.pos += steps;

        Ok(())
    }

    /// Change the buffer position
    pub fn seek(&mut self, pos: usize) -> Result<(),std::io::Error> {
        self.pos = pos;

        Ok(())
    }
    
    // Read the current position and step forward once
    fn read(&mut self) -> Result<u8,std::io::Error>{
        if self.pos >= 512 {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "End of buffer"));
        }
        let res = self.buf[self.pos];
        self.pos += 1;

        Ok(res)
    }
    
    /// Read a single byte and move the position one step forward
    pub fn read_u8(&mut self) -> Result<u8,std::io::Error> {
        if self.pos >= 512 {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "End of buffer"));
        }
        let res = self.buf[self.pos];
        self.pos += 1;
        Ok(res)
    }
    
    /// Get a single byte, without changing the buffer position
    pub fn get_byte(&mut self, pos: usize) -> Result<u8,std::io::Error> {
        if pos >= 512 {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "End of buffer"));
        }
        Ok(self.buf[pos])
    }

    /// Get a range of bytes
    pub fn get_byte_range(&mut self, start: usize, len: usize) -> Result<&[u8],std::io::Error> {
        if start + len >= 512 {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "End of buffer"));
        }
        Ok(&self.buf[start..start + len as usize])
    }

    /// Read two bytes, stepping two steps forward
    pub fn read_u16(&mut self) -> Result<u16,std::io::Error> {
        let res:u16 = ((match self.read() {
            Ok(s) => s,
            Err(e) => return Err(e),
        } as u16) << 8) | (match self.read() {
            Ok(s) => s,
            Err(e) => return Err(e),
        } as u16);

        Ok(res)
    }

    /// Read four bytes, stepping four steps forward
    pub fn read_u32(&mut self) -> Result<u32,std::io::Error> {
        let res:u32 = ((match self.read() {
                Ok(s) => s,
                Err(e) => return Err(e),
            } as u32) << 24)
            | ((match self.read() {
                Ok(s) => s,
                Err(e) => return Err(e),
            } as u32) << 16)
            | ((match self.read() {
                Ok(s) => s,
                Err(e) => return Err(e),
            } as u32) << 8)
            | ((match self.read() {
                Ok(s) => s,
                Err(e) => return Err(e),
            } as u32) << 0);

        Ok(res)
    }
    /// Read sixteen bytes, stepping sixteen steps forward
    pub fn read_u128(&mut self) -> Result<u128, std::io::Error> {
        let res:u128 = ((match self.read() {
                Ok(s) => s,
                Err(e) => return Err(e),
            } as u128) << 120)
            | ((match self.read() {
                Ok(s) => s,
                Err(e) => return Err(e),
            } as u128) << 112)
            | ((match self.read() {
                Ok(s) => s,
                Err(e) => return Err(e),
            } as u128) << 104)
            | ((match self.read() {
                Ok(s) => s,
                Err(e) => return Err(e),
            } as u128) << 96)
            | ((match self.read() {
                Ok(s) => s,
                Err(e) => return Err(e),
            } as u128) << 88)
            | ((match self.read() {
                Ok(s) => s,
                Err(e) => return Err(e),
            } as u128) << 80)
            | ((match self.read() {
                Ok(s) => s,
                Err(e) => return Err(e),
            } as u128) << 72)
            | ((match self.read() {
                Ok(s) => s,
                Err(e) => return Err(e),
            } as u128) << 64)
            | ((match self.read() {
                Ok(s) => s,
                Err(e) => return Err(e),
            } as u128) << 56)
            | ((match self.read() {
                Ok(s) => s,
                Err(e) => return Err(e),
            } as u128) << 48)
            | ((match self.read() {
                Ok(s) => s,
                Err(e) => return Err(e),
            } as u128) << 40)
            | ((match self.read() {
                Ok(s) => s,
                Err(e) => return Err(e),
            } as u128) << 32)
            | ((match self.read() {
                Ok(s) => s,
                Err(e) => return Err(e),
            } as u128) << 24)
            | ((match self.read() {
                Ok(s) => s,
                Err(e) => return Err(e),
            } as u128) << 16)
            | ((match self.read() {
                Ok(s) => s,
                Err(e) => return Err(e),
            } as u128) << 8)
            | ((match self.read() {
                Ok(s) => s,
                Err(e) => return Err(e),
            } as u128) << 0);
        Ok(res)
    }

    /// Read a qname
    ///
    /// The tricky part: Reading domain names, taking labels into consideration.
    /// Will take something like [3]www[6]google[3]com[0] and append
    /// www.google.com to outstr.
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

    /// Write a single byte and move the position one step forward
    fn write(&mut self, val: u8) -> Result<(),std::io::Error> {
        if self.pos >= 512 {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "End of buffer"));
        }
        self.buf[self.pos] = val;
        self.pos += 1;
        Ok(())
    }

    /// Write a single byte and move the position one step forward
    pub fn write_u8(&mut self, val: u8) -> Result<(),std::io::Error> {
        match self.write(val) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        Ok(())
    }

    /// Write two bytes and move the position two step forward
    pub fn write_u16(&mut self, val: u16) -> Result<(),std::io::Error> {
        match self.write((val >> 8) as u8) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match self.write((val & 0xFF) as u8) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        Ok(())
    }

    /// Write two bytes and move the position two step forward
    pub fn write_u32(&mut self, val: u32) -> Result<(),std::io::Error> {
        match self.write(((val >> 24) & 0xFF) as u8) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match self.write(((val >> 16) & 0xFF) as u8) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match self.write(((val >> 8) & 0xFF) as u8) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match self.write((val & 0xFF) as u8) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        Ok(())
    }

    /// Write sixteen bytes and move the position sixteen steps forward
    pub fn write_u128(&mut self, val: u128) -> Result<(), std::io::Error> {
        match self.write(((val >> 120) & 0xFF) as u8) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match self.write(((val >> 112) & 0xFF) as u8) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match self.write(((val >> 104) & 0xFF) as u8) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match self.write(((val >> 96) & 0xFF) as u8) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match self.write(((val >> 88) & 0xFF) as u8) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match self.write(((val >> 80) & 0xFF) as u8) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match self.write(((val >> 72) & 0xFF) as u8) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match self.write(((val >> 64) & 0xFF) as u8) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match self.write(((val >> 56) & 0xFF) as u8) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match self.write(((val >> 48) & 0xFF) as u8) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match self.write(((val >> 40) & 0xFF) as u8) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match self.write(((val >> 32) & 0xFF) as u8) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match self.write(((val >> 24) & 0xFF) as u8) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match self.write(((val >> 16) & 0xFF) as u8) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match self.write(((val >> 8) & 0xFF) as u8) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        match self.write((val & 0xFF) as u8) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        Ok(())
    }

    /// Write a qname
    ///
    /// The tricky part: Reading domain names, taking labels into consideration.
    /// Will take something like www.google.com and append
    /// [3]www[6]google[3]com[0] to outstr.
    pub fn write_qname(&mut self, qname: &str) -> Result<(),std::io::Error> {
        for label in qname.split('.') {
            let len = label.len();
            if len > 0x3f {
                return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "Single label exceeds 63 characters of length"));
            }

            match self.write_u8(len as u8) {
                Ok(s) => s,
                Err(e) => return Err(e),
            };
            for b in label.as_bytes() {
                match self.write_u8(*b) {
                    Ok(s) => s,
                    Err(e) => return Err(e),
                }
            }
        }

        match self.write_u8(0) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        Ok(())
    }
}