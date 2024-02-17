use std::net::Ipv4Addr;
use crate::dns::byte_packet_buffer::BytePacketBuffer;
use crate::dns::byte_packet_buffer_error::BytePacketBufferError;
use crate::dns::byte_packet_buffer_error::BytePacketBufferError::UnhandledDnsQueryType;
use crate::dns::query_type::QueryType;

// RFC 1035
// 4.1.3. Resource record format [Page 27]
//
// The answer, authority, and additional sections all share the same format: a
// variable number of resource records, where the number of records is specified
// in the corresponding count field in the header. Each resource record has the
// following format:
//
//                                     1  1  1  1  1  1
//       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                                               |
//     /                                               /
//     /                      NAME                     /
//     |                                               |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                      TYPE                     |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                     CLASS                     |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                      TTL                      |
//     |                                               |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                   RDLENGTH                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
//     /                     RDATA                     /
//     /                                               /
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//
// where:
//
// NAME            a domain name to which this resource record pertains.
//
// TYPE            two octets containing one of the RR type codes.  This field
//                 specifies the meaning of the data in the RDATA field.
//
// CLASS           two octets which specify the class of the data in the RDATA
//                 field.
//
// TTL             a 32 bit unsigned integer that specifies the time interval
//                 (in seconds) that the resource record may be cached before it
//                 should be discarded.  Zero values are interpreted to mean
//                 that the RR can only be used for the transaction in progress,
//                 and should not be cached.
//
// RDLENGTH        an unsigned 16 bit integer that specifies the length in
//                 octets of the RDATA field.
//
// RDATA           a variable length string of octets that describes the
//                 resource.  The format of this information varies according to
//                 the TYPE and CLASS of the resource record. For example, the
//                 if the TYPE is A and the CLASS is IN, the RDATA field is a 4
//                 octet ARPA Internet address.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[allow(dead_code)]
pub enum DnsRecord {
    // 0
    UNKNOWN {
        domain: String,
        qtype: u16,
        data_len: u16,
        ttl: u32,
    },
    // 1
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    },
}

impl DnsRecord {
    pub fn read(buffer: &mut BytePacketBuffer) -> Result<DnsRecord, BytePacketBufferError> {
        let mut domain = buffer.read_qname()?;

        let qtype_num = buffer.read_u16()?;
        let qtype = QueryType::from_num(qtype_num);

        // two octets which specify the class of the data in the RDATA field.
        // This is currently ignored here since we don't use it for any values
        // within our record.
        let _ = buffer.read_u16()?;

        let ttl = buffer.read_u32()?;
        let data_len = buffer.read_u16()?;

        match qtype {
            QueryType::A => {
                let raw_addr = buffer.read_u32()?;
                let addr = Ipv4Addr::new(
                    ((raw_addr >> 24) & 0xFF) as u8,
                    ((raw_addr >> 16) & 0xFF) as u8,
                    ((raw_addr >> 8) & 0xFF) as u8,
                    ((raw_addr >> 0) & 0xFF) as u8,
                );

                Ok(DnsRecord::A {
                    domain,
                    addr,
                    ttl,
                })
            }

            QueryType::UNKNOWN(_) => {
                buffer.step(data_len as usize);

                Ok(DnsRecord::UNKNOWN {
                    domain,
                    qtype: qtype_num,
                    data_len,
                    ttl,
                })
            }
            x => Err(UnhandledDnsQueryType(x))
        }
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<usize, BytePacketBufferError> {
        let start_pos = buffer.position();

        match *self {
            DnsRecord::A {
                ref domain,
                ref addr,
                ttl,
            } => {
                buffer.write_question_name(domain)?;
                buffer.write_u16(QueryType::A.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(4)?;

                let octets = addr.octets();
                buffer.write_u8(octets[0])?;
                buffer.write_u8(octets[1])?;
                buffer.write_u8(octets[2])?;
                buffer.write_u8(octets[3])?;
            }
            DnsRecord::UNKNOWN { .. } => {
                println!("Skipping record: {:?}", self);
            }
        }

        Ok(buffer.position() - start_pos)
    }
}