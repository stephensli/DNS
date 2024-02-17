#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResultCode {
    // No error condition.
    NoError = 0,
    // Format error - The name server was unable to interpret the query.
    FormatError = 1,
    //  Server failure - The name server was unable to process this query due to
    // a problem with the name server.
    ServerFailure = 2,
    // Name Error - Meaningful only for responses from an authoritative name
    // server, this code signifies that the domain name referenced in the
    // query does not exist.
    NameError = 3,
    // Not Implemented - The name server does not support the requested kind
    // of query.
    NotImplemented = 4,
    // Refused - The name server refuses to perform the specified operation for
    // policy reasons.  For example, a name server may not wish to provide the
    // information to the particular requester, or a name server may not wish to
    // perform a particular operation (e.g.,  zone transfer) for particular data.
    REFUSED = 5,
}

impl ResultCode {
    pub fn from_num(num: u8) -> ResultCode {
        match num {
            1 => ResultCode::FormatError,
            2 => ResultCode::ServerFailure,
            3 => ResultCode::NameError,
            4 => ResultCode::NotImplemented,
            5 => ResultCode::REFUSED,
            0 | _ => ResultCode::NoError,
        }
    }
}