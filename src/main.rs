use std::error::Error;
use std::net::UdpSocket;
use std::process::exit;
use crate::dns::byte_packet_buffer::{BytePacketBuffer};
use crate::dns::dns_packet::DnsPacket;
use crate::dns::dns_question::DnsQuestion;
use crate::dns::query_type::QueryType;
use crate::dns::query_class::QueryClass;
use crate::dns::result_code::ResultCode;

mod dns;


fn lookup(question_name: &str, question_type: QueryType) -> Result<DnsPacket, Box<dyn Error>> {
    let server = ("8.8.8.8", 53);
    let socket = UdpSocket::bind(("0.0.0.0", 43210))?;

    let mut packet = DnsPacket::new();

    packet.header.id = 6666;
    packet.header.questions = 1;
    packet.header.recursion_desired = false;

    let question = DnsQuestion::new(
        question_name.to_string(),
        question_type,
        QueryClass::IN);

    packet.questions.push(question);

    let mut request_buffer = BytePacketBuffer::new();

    packet.write(&mut request_buffer)?;
    socket.send_to(&request_buffer.buffer[0..request_buffer.position], server)?;

    let mut result_buffer = BytePacketBuffer::new();
    socket.recv_from(&mut result_buffer.buffer)?;

    Ok(DnsPacket::from_buffer(&mut result_buffer)?)
}

/// handle a single incoming packet request.
fn handle_query(socket: &UdpSocket) -> Result<(), Box<dyn Error>> {
    // With a socket ready, we can go ahead and read a packet. This will block
    // until one is received.
    let mut request_buffer = BytePacketBuffer::new();

    // The `recv_from` function will write the data into the provided buffer,
    // and will return the length of the data read as well as the source
    // address.
    //
    // We're not interested in the length, but we need to keep track of the
    // source in order to send our reply later on.
    let (_, src) = socket.recv_from(&mut request_buffer.buffer)?;

    // Next, `DnsPacket::from_buffer` is used ot parse the raw bytes into a
    // `DnsPacket`.
    let mut incoming_request = DnsPacket::from_buffer(&mut request_buffer)?;

    let mut packet = DnsPacket::new();

    packet.header.id = incoming_request.header.id;
    packet.header.recursion_desired = true;
    packet.header.recursion_available = true;
    packet.header.response = true;

    // In the normal case, exactly one question is present.
    if let Some(question) = incoming_request.questions.pop() {
        println!("received query: {:?}", question);

        // Since all is set up and as expected, the query can be forwarded to
        // the target server. There's always the possibility that the query will
        // fail, in which case, the `ServerFailed` response code will be set to
        // indicate as much to the client.
        //
        // If rather everything goes as planned, the question and response
        // records are copied into our response packet.
        if let Ok(result) = lookup(&question.q_name, question.q_type.clone()) {
            packet.questions.push(question);
            packet.header.rescode = result.header.rescode;

            for rec in result.answers {
                println!("Answer: {:?}", rec);
                packet.answers.push(rec);
            }
            for rec in result.authorities {
                println!("Authority: {:?}", rec);
                packet.authorities.push(rec);
            }
            for rec in result.resources {
                println!("Resource: {:?}", rec);
                packet.resources.push(rec);
            }
        } else {
            packet.header.rescode = ResultCode::ServerFailure;
        }
    } else {
        // Being mindful of how unreliable input data from arbitrary senders can
        // be, we need make sure that a question is actually present. If not, we
        // return `FORMERR` to indicate that the sender made something wrong.
        packet.header.rescode = ResultCode::FormatError;
    }

    // The only thing remaining is to encode our response and send it off!
    let mut result_buffer = BytePacketBuffer::new();
    packet.write(&mut result_buffer)?;

    let data = result_buffer.get_range(0, result_buffer.position())?;
    socket.send_to(data, src)?;

    Ok(())
}


fn main() -> Result<(), Box<dyn Error>> {
    // Bind an UDP socket on port 2053
    let socket = UdpSocket::bind(("0.0.0.0", 2053))?;

    // For now, queries are handled sequentially, so an infinite loop for servicing
    // requests is initiated.
    loop {
        match handle_query(&socket) {
            Ok(_) => {},
            Err(e) => eprintln!("An error occurred: {}", e),
        }
    }
}

