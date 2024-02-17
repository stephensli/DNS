use std::error::Error;
use std::fmt::{Display, Formatter};
use crate::dns::query_type::QueryType;

#[derive(Debug)]
pub enum BytePacketBufferError {
    // When reading the label names, the maximum jump counts have been reached
    // and has resulted in the termination of the packet. This is most likely
    // due to a circular jump injection.
    ExceededJumpCount(i32),
    // The requested values have resulted in the end of the buffer being met
    // or exceeding the end of the buffer.
    EndOfBuffer,
    // The returned query type for the DNS record is not being handled. For
    // example the returned type is A record and was ignored in the
    // implementation.
    UnhandledDnsQueryType(QueryType),

    // Each label name within a host being written to the package cannot exceed
    // the maximum length of 63 characters. The usize provided is the faulting
    // size length and value.
    //
    // index, length
    QueryLabelNameLengthExceeded(usize, usize),

    // To simplify implementations, the total length of a domain name (i.e.,
    // label octets and label length octets) is restricted to 255 octets or
    // fewer.
    //
    // The usize value is the size of the inputted length.
    QueryDomainNameLengthExceeded(usize),
}

impl Display for BytePacketBufferError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        return match self {
            BytePacketBufferError::QueryLabelNameLengthExceeded(index, length) => write!(f, "label in position {:?} exceeded 63 characters ({:?})", index, length),
            BytePacketBufferError::QueryDomainNameLengthExceeded(size)  => write!(f, "domain name exceeded 255 characters ({:?})", size),
            BytePacketBufferError::UnhandledDnsQueryType(t) => write!(f, "unhandled dns query type: {:?}", t),
            BytePacketBufferError::ExceededJumpCount(j) => write!(f, "exceeded jump count {:?}", j),
            BytePacketBufferError::EndOfBuffer => write!(f, "end of buffer"),
        }
    }
}

impl Error for BytePacketBufferError {}
