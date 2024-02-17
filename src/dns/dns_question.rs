use crate::dns::byte_packet_buffer::{BytePacketBuffer, BytePacketBufferError};
use crate::dns::query_type::QueryType;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    // A domain name represented as a sequence of labels, where each label
    // consists of a length octet followed by that number of octets.  The domain
    // name terminates with the zero length octet for the null label of the
    // root.  Note that this field may be an odd number of octets; no padding is
    // used.
    pub q_name: String,
    // A two octet code which specifies the type of the query. The values for
    // this field include all codes valid for a TYPE field, together with some
    // more general codes which can match more than one type of RR.
    pub q_type: QueryType,
}

impl DnsQuestion {
    pub fn new(q_name: String, q_type: QueryType) -> DnsQuestion {
        DnsQuestion {
            q_name,
            q_type,
        }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<(), BytePacketBufferError> {
        self.q_name = buffer.read_qname()?;
        self.q_type = QueryType::from_num(buffer.read_u16()?); // qtype
        let _ = buffer.read_u16()?; // class

        Ok(())
    }
}