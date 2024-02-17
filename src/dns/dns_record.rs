use std::net::Ipv4Addr;
use crate::dns::byte_packet_buffer::{BytePacketBuffer, BytePacketBufferError};
use crate::dns::byte_packet_buffer::BytePacketBufferError::UnhandledDnsQueryType;
use crate::dns::query_type::QueryType;

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
}