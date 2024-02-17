// A two octet code which specifies the type of the query. The values for this
// field include all codes valid for a TYPE field, together with some more
// general codes which can match more than one type of RR.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
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
            2 => QueryType::NS,
            3 => QueryType::MD,
            4 => QueryType::MF,
            5 => QueryType::CNAME,
            6 => QueryType::SOA,
            7 => QueryType::MB,
            8 => QueryType::MG,
            9 => QueryType::MR,
            10 => QueryType::NULL,
            11 => QueryType::WKS,
            12 => QueryType::PTR,
            13 => QueryType::HINFO,
            14 => QueryType::MINFO,
            15 => QueryType::MX,
            16 => QueryType::TXT,
            252 => QueryType::AXFR,
            253 => QueryType::MAILB,
            254 => QueryType::MAILA,
            255 => QueryType::EVERYTHING,
            _ => QueryType::UNKNOWN(num),
        }
    }
}