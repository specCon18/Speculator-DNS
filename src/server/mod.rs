use std::net::UdpSocket;
use crate::message::{byte_packet_buffer::BytePacketBuffer, header::{QRFlag, RAFlag, RDFlag,RCode}, DNSPacket, DNSQuestion, QRClass, QRType};

pub fn lookup(qname: &str, qtype: QRType, qclass: QRClass) -> Result<DNSPacket,std::io::Error> {
    // Forward queries to Google's public DNS
    let server = ("8.8.8.8", 53);

    let socket = UdpSocket::bind(("0.0.0.0", 43210))?;

    let mut packet = DNSPacket::new();

    packet.header.id = 6666;
    packet.header.qdcount = 1;
    packet.header.rd = RDFlag::NonDesired;
    packet.question.questions.push(DNSQuestion::new(qname.to_string(), qtype,qclass));

    let mut req_buffer = BytePacketBuffer::new();
    packet.write(&mut req_buffer)?;
    socket.send_to(&req_buffer.buf[0..req_buffer.pos], server)?;

    let mut res_buffer = BytePacketBuffer::new();
    socket.recv_from(&mut res_buffer.buf)?;

    DNSPacket::from_buffer(&mut res_buffer)
}

/// Handle a single incoming packet
pub fn handle_query(socket: &UdpSocket) -> Result<(),std::io::Error> {
    // With a socket ready, we can go ahead and read a packet. This will
    // block until one is received.
    let mut req_buffer = BytePacketBuffer::new();

    // The `recv_from` function will write the data into the provided buffer,
    // and return the length of the data read as well as the source address.
    // We're not interested in the length, but we need to keep track of the
    // source in order to send our reply later on.
    let (_, src) = socket.recv_from(&mut req_buffer.buf)?;

    // Next, `DnsPacket::from_buffer` is used to parse the raw bytes into
    // a `DnsPacket`.
    let mut request = DNSPacket::from_buffer(&mut req_buffer)?;

    // Create and initialize the response packet
    let mut packet = DNSPacket::new();
    packet.header.id = request.header.id;
    packet.header.rd = RDFlag::Desired;
    packet.header.ra = RAFlag::Available;
    packet.header.qr = QRFlag::Response;

    // In the normal case, exactly one question is present
    if let Some(question) = request.question.questions.pop() {
        println!("Received query: {:?}", question);

        // Since all is set up and as expected, the query can be forwarded to the
        // target server. There's always the possibility that the query will
        // fail, in which case the `SERVFAIL` response code is set to indicate
        // as much to the client. If rather everything goes as planned, the
        // question and response records as copied into our response packet.
        if let Ok(result) = lookup(&question.qname,question.qtype,question.qclass) {
            packet.question.questions.push(question);
            packet.header.rcode = result.header.rcode;

            for rec in result.answer.answers {
                println!("Answer: {:?}", rec);
                packet.answer.answers.push(rec);
            }
            for rec in result.authority.records {
                println!("Authority: {:?}", rec);
                packet.authority.records.push(rec);
            }
            for rec in result.additional.records {
                println!("Resource: {:?}", rec);
                packet.additional.records.push(rec);
            }
        } else {
            packet.header.rcode = RCode::ServFail;
        }
    }
    // Being mindful of how unreliable input data from arbitrary senders can be, we
    // need make sure that a question is actually present. If not, we return `FORMERR`
    // to indicate that the sender made something wrong.
    else {
        packet.header.rcode = RCode::FormErr;
    }

    // The only thing remaining is to encode our response and send it off!
    let mut res_buffer = BytePacketBuffer::new();
    packet.write(&mut res_buffer)?;

    let len = res_buffer.pos();
    let data = res_buffer.get_byte_range(0, len)?;

    socket.send_to(data, src)?;

    Ok(())
}