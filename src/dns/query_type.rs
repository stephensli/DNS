// A two octet code which specifies the type of the query. The values for this
// field include all codes valid for a TYPE field, together with some more
// general codes which can match more than one type of RR.
#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy)]
pub enum QueryType {
    UNKNOWN(u16),
    // 1 a host address
    A,
    // 2 an authoritative name server
    NS,
    // 3 a mail destination (Obsolete - use MX)
    MD,
    // 4 a mail forwarder (Obsolete - use MX)
    MF,
    // 5 the canonical name for an alias
    CNAME,
    // 6 marks the start of a zone of authority
    SOA,
    // 7 a mailbox domain name (EXPERIMENTAL)
    MB,
    // 8 a mail group member (EXPERIMENTAL)
    MG,
    // 9 a mail rename domain name (EXPERIMENTAL)
    MR,
    // 10 a null RR (EXPERIMENTAL)
    NULL,
    // 11 a well known service description
    WKS,
    // 12 a domain name pointer
    PTR,
    // 13 host information
    HINFO,
    // 14 mailbox or mail list information
    MINFO,
    // 15 mail exchange
    MX,
    // 16 text strings
    TXT,
    // 252 A request for a transfer of an entire zone
    AXFR,
    // 253 A request for mailbox-related records (MB, MG or MR)
    MAILB,
    // 254 A request for mail agent RRs (Obsolete - see MX)
    MAILA,
    // 255 A request for all records
    EVERYTHING,
}

impl QueryType {
    pub fn to_num(&self) -> u16 {
        match *self {
            QueryType::UNKNOWN(x) => x,
            QueryType::A => 1,
            QueryType::NS => 2,
            QueryType::MD => 3,
            QueryType::MF => 4,
            QueryType::CNAME => 5,
            QueryType::SOA => 6,
            QueryType::MB => 7,
            QueryType::MG => 8,
            QueryType::MR => 9,
            QueryType::NULL => 10,
            QueryType::WKS => 11,
            QueryType::PTR => 12,
            QueryType::HINFO => 13,
            QueryType::MINFO => 14,
            QueryType::MX => 15,
            QueryType::TXT => 16,
            QueryType::AXFR => 252,
            QueryType::MAILB => 253,
            QueryType::MAILA => 254,
            QueryType::EVERYTHING => 255,
        }
    }

    pub fn from_num(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
            _ => QueryType::UNKNOWN(num),
        }
    }
}