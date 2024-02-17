// https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.4
//
// CLASS fields appear in resource records.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum QueryClass {
    UNKNOWN(u16),
    // 1 The Internet
    IN,
    // 2 The CSNET class (Obsolete - used only for examples in some obsolete
    // RFCs)
    CS,
    // 3 The CHAOS class
    CH,
    // 4 Hesiod [Dyer 87]
    HS,
}

impl QueryClass {
    pub fn to_num(&self) -> u16 {
        match *self {
            QueryClass::UNKNOWN(x) => x,
            QueryClass::IN => 1,
            QueryClass::CS => 2,
            QueryClass::CH => 3,
            QueryClass::HS => 4,
        }
    }

    pub fn from_num(num: u16) -> QueryClass {
        match num {
            1 => QueryClass::IN,
            2 => QueryClass::CS,
            3 => QueryClass::CH,
            4 => QueryClass::HS,
            _ => QueryClass::UNKNOWN(num),
        }
    }
}