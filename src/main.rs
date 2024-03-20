mod message;

use std::net::UdpSocket;

use crate::message::{byte_packet_buffer::BytePacketBuffer, DNSPacket, DNSQuestion, QRClass, QRType};


fn main() -> Result<(),std::io::Error>{
    // Perform an A query for google.com
    let qname:String = "yahoo.com".to_string();
    let qtype:QRType = QRType::MX;
    let qclass:QRClass = QRClass::IN;

    // Using googles public DNS server
    let server = ("8.8.8.8", 53);

    // Bind a UDP socket to an arbitrary port
    let socket = UdpSocket::bind(("0.0.0.0", 43210))?;

    // Build our query packet. It's important that we remember to set the
    // `recursion_desired` flag. As noted earlier, the packet id is arbitrary.
    let mut packet:DNSPacket = DNSPacket::new();

    packet.header.id = 6666;
    packet.header.qdcount = 1;
    packet.header.rd = message::header::RDFlag::NonDesired;
    packet.question.questions.push(DNSQuestion::new(qname, qtype, qclass));

    // Use our new write method to write the packet to a buffer...
    let mut req_buffer: BytePacketBuffer = BytePacketBuffer::new();
    packet.write(&mut req_buffer)?;

    // ...and send it off to the server using our socket:
    socket.send_to(&req_buffer.buf[0..req_buffer.pos], server)?;

    // To prepare for receiving the response, we'll create a new `BytePacketBuffer`,
    // and ask the socket to write the response directly into our buffer.
    let mut res_buffer: BytePacketBuffer = BytePacketBuffer::new();
    socket.recv_from(&mut res_buffer.buf)?;

    // As per the previous section, `DnsPacket::from_buffer()` is then used to
    // actually parse the packet after which we can print the response.
    let res_packet = DNSPacket::from_buffer(&mut res_buffer)?;
    println!("{:#?}", res_packet.header);

    for q in res_packet.question.questions {
        println!("{:#?}", q);
    }
    for rec in res_packet.answer.answers {
        println!("{:#?}", rec);
    }
    for rec in res_packet.authority.records {
        println!("{:#?}", rec);
    }
    for rec in res_packet.additional.records {
        println!("{:#?}", rec);
    }

    Ok(())
    // let mut f = File::open("response_packet.txt")?;
    // let mut buffer = BytePacketBuffer::new();
    // f.read(&mut buffer.buf)?;

    // let packet = DNSPacket::from_buffer(&mut buffer)?;
    // println!("{:#?}", packet.header);

    // for q in packet.question.questions {
    //     println!("{:#?}", q);
    // }
    // for rec in packet.answer.answers {
    //     println!("{:#?}", rec);
    // }
    // for rec in packet.authority.records {
    //     println!("{:#?}", rec);
    // }
    // for rec in packet.additional.records {
    //     println!("{:#?}", rec);
    // }

    // Ok(())
}
