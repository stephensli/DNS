use crate::dns::byte_packet_buffer::{BytePacketBuffer};
use crate::dns::byte_packet_buffer_error::BytePacketBufferError;
use crate::dns::result_code::ResultCode;



/// RFC 1035
/// 4.1.1. Header section format [Page 27]
///
/// The header contains the following fields:
///
/// 1  1  1  1  1  1
/// 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                      ID                       |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    QDCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    ANCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    NSCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    ARCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#[derive(Clone, Debug)]
pub struct DnsHeader {
    /// A 16 bit identifier assigned by the program that generates any kind of
    /// query. This identifier is copied the corresponding reply and can be used
    /// by the requester to match up replies to outstanding queries.
    pub id: u16,

    /// This bit may be set in a query and is copied into the response. If RD is
    /// set, it directs the name server to pursue the query recursively.
    /// Recursive query support is optional.
    pub recursion_desired: bool,

    /// This bit is set or cleared in a response, and denotes whether recursive
    /// query support is available in the name server.
    pub recursion_available: bool,

    /// This bit specifies that this message was truncated due to length greater
    /// than that permitted on the transmission channel.
    pub truncated_message: bool,

    /// this bit is valid in responses, and specifies that the responding name
    /// server is an authority for the domain name in question section.
    ///
    /// Note that the contents of the answer section may have multiple owner
    /// names because of aliases. The AA bit corresponds to the name which
    /// matches the query name, or the first owner name in the answer section.
    pub authoritative_answer: bool,

    /// A four bit field that specifies kind of query in this message. This
    /// value is set by the originator of a query and copied into the response.
    /// The values are:
    ///
    /// * 0     - A standard query (QUERY).
    /// * 1     - An inverse query (IQUERY).
    /// * 2     - A server status request (STATUS).
    /// * 3-15  - Reserved for future use.
    pub opcode: u8,

    /// A one bit field that specifies whether this message is a query (0), or a
    /// response (1).
    pub response: bool,

    /// This 4 bit field is set as part of responses.
    pub rescode: ResultCode,

    /// 1 bit
    pub checking_disabled: bool,

    /// 1 bit
    pub authed_data: bool,

    /// This bit  is reserved for future use. Must be zero in all queries and
    /// responses.
    pub z: bool,

    /// An unsigned 16-bit integer specifying the number of entries in the
    /// question section.
    pub questions: u16,

    /// An unsigned 16-bit integer specifying the number of resource records in
    /// the answer section.
    pub answers: u16,

    /// An unsigned 16-bit integer specifying the number of name server resource
    /// records in the authority records section.
    pub authoritative_entries: u16,

    /// An unsigned 16-bit integer specifying the number of resource records in
    /// the additional records section.
    pub resource_entries: u16,
}

/// https://www.ietf.org/rfc/rfc1035.txt
///
/// RFC 1035
/// Domain Implementation and Specification
/// November 1987
///
/// 4.1.1. Header section format
impl DnsHeader {
    pub fn new() -> DnsHeader {
        DnsHeader {
            id: 0,

            recursion_desired: false,
            truncated_message: false,
            authoritative_answer: false,
            opcode: 0,
            response: false,

            rescode: ResultCode::NoError,
            checking_disabled: false,
            authed_data: false,
            z: false,
            recursion_available: false,

            questions: 0,
            answers: 0,
            authoritative_entries: 0,
            resource_entries: 0,
        }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<(), BytePacketBufferError> {
        self.id = buffer.read_u16()?;

        let flags = buffer.read_u16()?;
        let a = (flags >> 8) as u8;
        let b = (flags & 0xFF) as u8;
        self.recursion_desired = (a & (1 << 0)) > 0;
        self.truncated_message = (a & (1 << 1)) > 0;
        self.authoritative_answer = (a & (1 << 2)) > 0;
        self.opcode = (a >> 3) & 0x0F;
        self.response = (a & (1 << 7)) > 0;

        self.rescode = ResultCode::from_num(b & 0x0F);
        self.checking_disabled = (b & (1 << 4)) > 0;
        self.authed_data = (b & (1 << 5)) > 0;
        self.z = (b & (1 << 6)) > 0;
        self.recursion_available = (b & (1 << 7)) > 0;

        self.questions = buffer.read_u16()?;
        self.answers = buffer.read_u16()?;
        self.authoritative_entries = buffer.read_u16()?;
        self.resource_entries = buffer.read_u16()?;

        Ok(())
    }


    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<(), BytePacketBufferError> {
        buffer.write_u16(self.id)?;

        buffer.write_u8(
            (self.recursion_desired as u8)
                | ((self.truncated_message as u8) << 1)
                | ((self.authoritative_answer as u8) << 2)
                | (self.opcode << 3)
                | ((self.response as u8) << 7) as u8,
        )?;

        buffer.write_u8(
            (self.rescode as u8)
                | ((self.checking_disabled as u8) << 4)
                | ((self.authed_data as u8) << 5)
                | ((self.z as u8) << 6)
                | ((self.recursion_available as u8) << 7),
        )?;

        buffer.write_u16(self.questions)?;
        buffer.write_u16(self.answers)?;
        buffer.write_u16(self.authoritative_entries)?;
        buffer.write_u16(self.resource_entries)
    }
}