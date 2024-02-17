use std::net::{Ipv4Addr, Ipv6Addr};
use crate::dns::byte_packet_buffer::BytePacketBuffer;
use crate::dns::byte_packet_buffer_error::BytePacketBufferError;
use crate::dns::query_class::QueryClass;
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
// NAME            A domain name to which this resource record pertains.
//
// TYPE            Two octets containing one of the RR type codes. This field
//                 specifies the meaning of the data in the RDATA field.
//
// CLASS           Two octets which specify the class of the data in the RDATA
//                 field.
//
// TTL             A 32-bit unsigned integer that specifies the time interval
//                 (in seconds) that the resource record may be cached before it
//                 should be discarded. Zero values are interpreted to mean that
//                 the RR can only be used for the transaction in progress,
//                 and should not be cached.
//
// RDLENGTH        An unsigned 16-bit integer that specifies the length in
//                 octets of the RDATA field.
//

// RDATA           A variable length string of octets that describes the
//                 resource. The format of this information varies according to
//                 the TYPE and CLASS of the resource record. For example,
//                 if the TYPE is A and the CLASS is IN, the RDATA field is a 4
//                 octet ARPA Internet address.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[allow(dead_code)]
pub enum DnsRecord {
    // 0
    UNHANDLED {
        domain: String,
        qtype: QueryType,
        data_len: u16,
        ttl: u32,
    },
    // Code 1
    //
    // A 32 bit IPv4 address is encoded in the data portion of an A resource
    // record in network byte order.
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    },
    // Code 2
    // https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.11
    //
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    // /                   NSDNAME                     /
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    //
    // NSDNAME: A <domain-name> which specifies a host which should be
    // authoritative for the specified class and domain.
    NS {
        domain: String,
        host: String,
        ttl: u32,
    },
    // Code 5
    // https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.1
    //
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    // /                     CNAME                     /
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    //
    // CNAME: A <domain-name> which specifies the canonical or primary name for
    // the owner.  The owner name is an alias.
    CNAME {
        domain: String,
        host: String,
        ttl: u32,
    },
    // Code 15
    // https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.9
    //
    //  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    //  |                  PREFERENCE                   |
    //  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    //  /                   EXCHANGE                    /
    //  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    //
    // PREFERENCE: A 16 bit integer which specifies the preference given to this
    // RR among others at the same owner. Lower values are preferred.
    //
    // EXCHANGE A <domain-name> which specifies a host willing to act as a mail
    // exchange for the owner name.
    MX {
        domain: String,
        preference: u16,
        host: String,
        ttl: u32,
    },
    // 28
    //
    // A 128 bit IPv6 address is encoded in the data portion of an AAAA resource
    // record in network byte order (high-order byte first).
    //
    // An AAAA query for a specified domain name in the Internet class returns
    // all associated AAAA resource records in the answer section of a response.
    //
    // A type AAAA query does not trigger additional section processing.
    //
    // https://datatracker.ietf.org/doc/html/rfc3596#section-2.2
    AAAA {
        domain: String,
        addr: Ipv6Addr,
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

                Ok(DnsRecord::A { domain, addr, ttl })
            }

            QueryType::AAAA => {
                let raw_addr1 = buffer.read_u32()?;
                let raw_addr2 = buffer.read_u32()?;
                let raw_addr3 = buffer.read_u32()?;
                let raw_addr4 = buffer.read_u32()?;

                let addr = Ipv6Addr::new(
                    ((raw_addr1 >> 16) & 0xFFFF) as u16,
                    ((raw_addr1 >> 0) & 0xFFFF) as u16,
                    ((raw_addr2 >> 16) & 0xFFFF) as u16,
                    ((raw_addr2 >> 0) & 0xFFFF) as u16,
                    ((raw_addr3 >> 16) & 0xFFFF) as u16,
                    ((raw_addr3 >> 0) & 0xFFFF) as u16,
                    ((raw_addr4 >> 16) & 0xFFFF) as u16,
                    ((raw_addr4 >> 0) & 0xFFFF) as u16,
                );

                Ok(DnsRecord::AAAA { domain, addr, ttl })
            }
            QueryType::NS => {
                let host = buffer.read_qname()?;
                Ok(DnsRecord::NS { domain, host, ttl })
            }
            QueryType::CNAME => {
                let host = buffer.read_qname()?;
                Ok(DnsRecord::CNAME { domain, host, ttl })
            }
            QueryType::MX => {
                let priority = buffer.read_u16()?;
                let host = buffer.read_qname()?;
                Ok(DnsRecord::MX { domain, preference: priority, host, ttl })
            }

            _ => {
                // For every single unhandled message within the buffer, go and
                // skip the size of the data and continue execution.
                buffer.step(data_len as usize);

                let qtype = QueryType::from_num(qtype_num);
                Ok(DnsRecord::UNHANDLED { domain, qtype, data_len, ttl })
            }
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
            DnsRecord::UNHANDLED { .. } => {
                println!("Skipping record: {:?}", self);
            }

            DnsRecord::NS {
                ref domain,
                ref host,
                ttl,
            } => {
                buffer.write_question_name(domain)?;
                buffer.write_u16(QueryType::NS.to_num())?;
                buffer.write_u16(QueryClass::IN.to_num())?;
                buffer.write_u32(ttl)?;

                // Set the size as zero for the DNS record to be zero, since we
                // don't explicitly know the size until after we have written
                // all the data.
                let pos = buffer.position();
                buffer.write_u16(0)?;

                buffer.write_question_name(host)?;

                // Determine the size by given position + 2, which is the zero
                // value terminator the question name and value difference from
                // the position - pos execution.
                let size = (buffer.position() - (pos + 2)) as u16;
                buffer.set_u16(pos, size)?;
            }

            DnsRecord::CNAME {
                ref domain,
                ref host,
                ttl,
            } => {
                buffer.write_question_name(domain)?;
                buffer.write_u16(QueryType::CNAME.to_num())?;
                buffer.write_u16(QueryClass::IN.to_num())?;
                buffer.write_u32(ttl)?;

                // Set the size as zero for the DNS record to be zero, since we
                // don't explicitly know the size until after we have written
                // all the data.
                let pos = buffer.position();
                buffer.write_u16(0)?;

                buffer.write_question_name(host)?;

                // Determine the size by given position + 2, which is the zero
                // value terminator the question name and value difference from
                // the position - pos execution.
                let size = (buffer.position() - (pos + 2)) as u16;
                buffer.set_u16(pos, size)?;
            }
            DnsRecord::MX {
                ref domain,
                ref host,
                preference: priority,
                ttl,
            } => {
                buffer.write_question_name(domain)?;
                buffer.write_u16(QueryType::MX.to_num())?;
                buffer.write_u16(QueryClass::IN.to_num())?;
                buffer.write_u32(ttl)?;

                // Set the size as zero for the DNS record to be zero, since we
                // don't explicitly know the size until after we have written
                // all the data.
                let pos = buffer.position();
                buffer.write_u16(0)?;

                buffer.write_u16(priority)?;
                buffer.write_question_name(host)?;

                // Determine the size by given position + 2, which is the zero
                // value terminator the question name and value difference from
                // the position - pos execution.
                let size = buffer.position() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            }
            DnsRecord::AAAA {
                ref domain,
                ref addr,
                ttl,
            } => {
                buffer.write_question_name(domain)?;
                buffer.write_u16(QueryType::AAAA.to_num())?;
                buffer.write_u16(QueryClass::IN.to_num())?;
                buffer.write_u32(ttl)?;

                // Ipv6 addresses are always 16 bytes long
                buffer.write_u16(16)?;

                for octet in &addr.segments() {
                    buffer.write_u16(*octet)?;
                }
            }
        }

        Ok(buffer.position() - start_pos)
    }
}