use std::net::{IpAddr, Ipv4Addr};
use crate::dns::byte_packet_buffer::BytePacketBuffer;
use crate::dns::byte_packet_buffer_error::BytePacketBufferError;
use crate::dns::dns_header::DnsHeader;
use crate::dns::dns_question::DnsQuestion;
use crate::dns::dns_record::DnsRecord;
use crate::dns::query_class::QueryClass;
use crate::dns::query_type::QueryType;

/// RFC 1035
/// 4.1. Format [Page 24]
///
/// All communications inside the domain protocol are carried in a single format
/// called a message. The top level format of message is divided into 5 sections
/// (some of which are empty in certain cases) shown below:
///
///     +---------------------+
///     |        Header       |
///     +---------------------+
///     |       Question      | the question for the name server
///     +---------------------+
///     |        Answer       | RRs answering the question
///     +---------------------+
///     |      Authority      | RRs pointing toward an authority
///     +---------------------+
///     |      Additional     | RRs holding additional information
///     +---------------------+
///
/// The header section is always present. The header includes fields that specify
/// which of the remaining sections are present, and also specify whether the
/// message is a query or a response, a standard query or some other opcode, etc.
///
/// The names of the sections after the header are derived from their use in
/// standard queries. The question section contains fields that describe a
/// question to a name server. These fields are a query type (QTYPE), a query
/// class (QCLASS), and a query domain name (QNAME). The last three sections have
/// the same format: a possibly empty list of concatenated resource records
/// (RRs). The answer section contains RRs that answer the question; the
/// authority section contains RRs that point toward an authoritative name
/// server; the additional records section contains RRs which relate to the
/// query, but are not strictly answers for the question.
#[derive(Clone, Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>,
}

impl DnsPacket {
    pub fn new() -> DnsPacket {
        DnsPacket {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }

    /// It's useful to be able to pick a random A record from a packet. When we
    /// get multiple IPs for a single name, it doesn't matter which one we
    /// choose, so in those cases we can now pick one at random.
    pub fn get_random_a(&self) -> Option<Ipv4Addr> {
        self.answers.iter().filter_map(|record| match record {
            DnsRecord::A { addr, .. } => Some(*addr),
            _ => None
        }).next()
    }

    /// A helper function which returns an iterator over all name servers in
    /// the authorities section, represented as (domain, host) tuples
    pub fn get_ns<'a>(&'a self, question_name: &'a str) -> impl Iterator<Item=(&'a str, &'a str)> {
        self.authorities.iter().
            // In practice, these are always NS records, in well formatted
            // packages. This will ensure to be explicit and convert the
            // records into tuples which only has the data we require to make
            // it easy to work.
            filter_map(|record| match record {
                DnsRecord::NS { domain, host, .. } => Some((domain.as_str(), host.as_str())),
                _ => None
            })
            // Discard servers which aren't authoritative to our query
            .filter(move |(domain, _)| question_name.ends_with(*domain))
    }

    /// Return resolved name servers based on the question name. Most name
    /// servers will include the IP address for the NS but not always.
    pub fn get_resolved_ns(&self, question_name: &str) -> Option<Ipv4Addr> {
        self.get_ns(question_name)
            // Now we need to look for a matching A record in the additional
            // section. Since we just want the first valid record, we can just build
            // a stream of matching records.
            .flat_map(|(_, host)| {
                self.resources.iter().
                    // Filter for A records where the domain match the host
                    // of the NS record that we are currently processing
                    filter_map(move |record| match record {
                        DnsRecord::A { domain, addr, .. }  if domain == host => Some(*addr),
                        _ => None
                    })
            }).map(|addr| addr)
            // Finally, pick the first valid entry.
            .next()
    }

    /// However, not all name servers are as that nice. In certain cases there
    /// won't be any A records in the additional section, and we'll have to
    /// perform *another* lookup in the midst. For this, we introduce a method
    /// for returning the host name of an appropriate name server.
    pub fn get_unresolved_ns<'a>(&'a self, qname: &'a str) -> Option<&'a str> {
        // Get an iterator over the nameservers in the authorities section
        self.get_ns(qname)
            .map(|(_, host)| host)
            // Finally, pick the first valid entry
            .next()
    }

    pub fn from_buffer(buffer: &mut BytePacketBuffer) -> Result<DnsPacket, BytePacketBufferError> {
        let mut result = DnsPacket::new();
        result.header.read(buffer)?;

        for _ in 0..result.header.questions {
            let mut question = DnsQuestion::new(
                "".to_string(),
                QueryType::UNKNOWN(0),
                QueryClass::UNKNOWN(0),
            );

            question.read(buffer)?;
            result.questions.push(question);
        }

        for _ in 0..result.header.answers {
            let rec = DnsRecord::read(buffer)?;
            result.answers.push(rec);
        }
        for _ in 0..result.header.authoritative_entries {
            let rec = DnsRecord::read(buffer)?;
            result.authorities.push(rec);
        }
        for _ in 0..result.header.resource_entries {
            let rec = DnsRecord::read(buffer)?;
            result.resources.push(rec);
        }

        Ok(result)
    }

    pub fn write(&mut self, buffer: &mut BytePacketBuffer) -> Result<(), BytePacketBufferError> {
        self.header.questions = self.questions.len() as u16;
        self.header.answers = self.answers.len() as u16;
        self.header.authoritative_entries = self.authorities.len() as u16;
        self.header.resource_entries = self.resources.len() as u16;

        self.header.write(buffer)?;

        for question in &self.questions {
            question.write(buffer)?;
        }
        for rec in &self.answers {
            rec.write(buffer)?;
        }
        for rec in &self.authorities {
            rec.write(buffer)?;
        }
        for rec in &self.resources {
            rec.write(buffer)?;
        }

        Ok(())
    }
}
