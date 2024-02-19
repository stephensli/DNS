use crate::dns::byte_packet_buffer::BytePacketBuffer;
use crate::dns::byte_packet_buffer_error::BytePacketBufferError;
use crate::dns::query_class::QueryClass;
use crate::dns::query_type::QueryType;

/// RFC 1035
/// 4.1.1. Header section format [Page 27]
///
/// The question section is used to carry the "question" in most queries,
/// i.e., the parameters that define what is being asked.  The section
/// contains QDCOUNT (usually 1) entries, each of the following format:
///
///                                 1  1  1  1  1  1
///   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                                               |
/// /                     QNAME                     /
/// /                                               /
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                     QTYPE                     |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                     QCLASS                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    //// A domain name represented as a sequence of labels, where each label
    //// consists of a length octet followed by that number of octets. The domain
    //// name terminates with the zero length octet for the null label of the
    //// root. Note that this field may be an odd number of octets; no padding is
    //// used.
    pub q_name: String,
    /// A two octet code which specifies the type of the query. The values for
    /// this field include all codes valid for a TYPE field, together with some
    /// more general codes which can match more than one type of RR.
    pub q_type: QueryType,
    /// A two octet code that specifies the class of the query. For example, the
    /// QCLASS field is IN for the Internet.
    pub q_class: QueryClass,
}

impl DnsQuestion {
    pub fn new(q_name: String, q_type: QueryType, q_class: QueryClass) -> DnsQuestion {
        DnsQuestion {
            q_name,
            q_type,
            q_class,
        }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<(), BytePacketBufferError> {
        self.q_name = buffer.read_question_name()?;
        self.q_type = QueryType::from_num(buffer.read_u16()?); // qtype
        self.q_class = QueryClass::from_num(buffer.read_u16()?); // class

        Ok(())
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<(), BytePacketBufferError> {
        buffer.write_question_name(&self.q_name)?;

        let type_number = self.q_type.to_num();
        let class_number = self.q_class.to_num();

        buffer.write_u16(type_number)?;
        buffer.write_u16(class_number)?;

        Ok(())
    }
}