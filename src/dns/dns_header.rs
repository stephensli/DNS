use crate::dns::byte_packet_buffer::{BytePacketBuffer, BytePacketBufferError};
use crate::dns::result_code::ResultCode;

#[derive(Clone, Debug)]
pub struct DnsHeader {
    // 16 bits
    pub id: u16,

    // 1 bit
    pub recursion_desired: bool,

    // 1 bit
    pub truncated_message: bool,

    // 1 bit
    pub authoritative_answer: bool,

    // 4 bits
    pub opcode: u8,

    // 1 bit
    pub response: bool,

    // 4 bits
    pub rescode: ResultCode,

    // 1 bit
    pub checking_disabled: bool,

    // 1 bit
    pub authed_data: bool,

    // 1 bit
    pub z: bool,

    // 1 bit
    pub recursion_available: bool,

    // 16 bits
    pub questions: u16,

    // 16 bits
    pub answers: u16,

    // 16 bits
    pub authoritative_entries: u16,

    // 16 bits
    pub resource_entries: u16,
}

impl DnsHeader {
    pub fn new() -> DnsHeader {
        DnsHeader {
            id: 0,

            recursion_desired: false,
            truncated_message: false,
            authoritative_answer: false,
            opcode: 0,
            response: false,

            rescode: ResultCode::NOERROR,
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
}