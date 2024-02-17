use std::error::Error;
use std::fmt::{Display, Formatter};
use crate::dns::byte_packet_buffer::BytePacketBufferError::{EndOfBuffer, ExceededJumpCount};
use crate::dns::query_type::QueryType;

#[derive(Debug)]
pub enum BytePacketBufferError {
    // When reading the label names, the maximum jump counts have been reached
    // and has resulted in the termination of the packet. This is most likely
    // due to a circular jump injection.
    ExceededJumpCount(i32),
    // The requested values have resulted in the end of the buffer being met
    // or exceeding the end of the buffer.
    EndOfBuffer,
    // The returned query type for the DNS record is not being handled. For
    // example the returned type is A record and was ignored in the
    // implementation.
    UnhandledDnsQueryType(QueryType)
}

impl Display for BytePacketBufferError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

impl Error for BytePacketBufferError {

}

pub struct BytePacketBuffer {
    pub buffer: [u8; 512],
    pub position: usize,
}


impl BytePacketBuffer {
    // Create a fresh buffer for holding a dns record package contents and a
    // field for keeping track of where we are at.
    pub fn new() -> BytePacketBuffer {
        BytePacketBuffer {
            buffer: [0; 512],
            position: 0,
        }
    }

    // Get the current position within the buffer.
    fn position(&self) -> usize {
        self.position
    }

    // Step the buffer position forward a specific number of steps.
    pub fn step(&mut self, step: usize) {
        self.position += step;
    }

    // Change the buffer position to the given value.
    fn seek(&mut self, position: usize) {
        self.position = position
    }

    // Read a single byte and then move the position one step forward.
    fn read(&mut self) -> Result<u8, BytePacketBufferError> {
        if self.position >= 512 {
            return Err(EndOfBuffer);
        }

        let result = self.buffer[self.position];
        self.step(1);

        Ok(result)
    }

    // Get a single byte from the buffer without performing any additional
    // forward stepping.
    fn get(&mut self, position: usize) -> Result<u8, BytePacketBufferError> {
        if position >= 512 {
            return Err(EndOfBuffer);
        }

        Ok(self.buffer[position])
    }

    // Get a range of bytes from the current buffer.
    fn get_range(&mut self, start: usize, length: usize) -> Result<&[u8], BytePacketBufferError> {
        if start + length >= 512 {
            return Err(EndOfBuffer);
        }

        Ok(&self.buffer[start..start + length])
    }

    // Read two bytes, stepping two steps forward
    pub fn read_u16(&mut self) -> Result<u16, BytePacketBufferError> {
        let result = ((self.read()? as u16) << 8) | (self.read()? as u16);
        Ok(result)
    }

    // Read four bytes, stepping four steps forward
    pub fn read_u32(&mut self) -> Result<u32, BytePacketBufferError> {
        let res = ((self.read()? as u32) << 24)
            | ((self.read()? as u32) << 16)
            | ((self.read()? as u32) << 8)
            | ((self.read()? as u32) << 0);

        Ok(res)
    }

    /// Read a qname
    ///
    /// The Reading domain names, taking labels into consideration.
    /// Will take something like [3]www[6]google[3]com[0] and append
    /// www.google.com to outstr.
    pub fn read_qname(&mut self) -> Result<String, BytePacketBufferError> {
        // Since we might encounter jumps, we'll keep track of our position
        // locally as opposed to using the position within the struct. This
        // allows us to move the shared position to a point past our current
        // qname, while keeping track of our progress on the current qname
        // using this variable.
        let mut current_position = self.position();

        let mut jumped = false;
        let mut jumps_performed = 0;

        // DNS packets are not directly trusted and every step needs to be
        // validated. For example, a cycle in the jump instructions can be
        // implemented resulting in an infinite loop. This allows a guard
        // against it.
        let max_jumps = 5;

        // Our delimiter which we append for each label. Since we don't want a
        // dot at the beginning of the domain name we'll leave it empty for now
        // and set it to "." at the end of the first iteration.
        let mut delimiter = "";
        let mut qname = String::new();

        loop {
            if jumps_performed > max_jumps {
                return Err(ExceededJumpCount(max_jumps));
            }

            // At  this point we are always at the beginning of a label. Recall
            // that labels start with a length of the bytes.
            let word_length = self.get(current_position)?;

            // if length has the two most significant bits set, it represents a
            // jump to some other offset in the packet, and we will have to seek
            // to it.
            //
            // 0xC0 = 11000000
            //
            // E.g. 8 bits with the first values set to 1.
            if (word_length & 0xC0) == 0xC0 {
                // update the buffer position to a point past the current label.
                // We don't need to touch it any further.
                if !jumped {
                    self.seek(current_position + 2)
                }

                // Read another byte, calculate offset and perform the jump by
                // updating our local positional value.
                let second_byte = self.get(current_position + 1)? as u16;
                let offset = (((word_length as u16) ^ 0xc0) << 8) | second_byte;
                current_position = offset as usize;

                jumped = true;
                jumps_performed += 1;

                continue;
            }

            // The base scenario, where we are reading a single label and
            // appending it to our resulting value.
            //
            // Start by moving a single byte forward to move past the length
            // byte.
            current_position += 1;

            // Domain names are terminated by an empty label value of length 0.
            // So if the length byte is zero, we are done.
            if word_length == 0 {
                break;
            }

            // Append the delimiter to our finalised string buffer first. This
            // will be our dot for all situations other than the first append.
            qname.push_str(delimiter);

            let str_buffer = self.get_range(current_position, word_length as usize)?;
            qname.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

            // Update our delimiter for all future appends.
            delimiter = ".";

            // move forward the full length of the label.
            current_position += word_length as usize;
        }

        if !jumped {
            self.seek(current_position);
        }

        Ok(qname)
    }
}