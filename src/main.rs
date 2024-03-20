mod records;
mod message;

use std::fs::File;
use std::io::Read;

use crate::message::{DNSPacket, byte_packet_buffer::BytePacketBuffer};


fn main() -> Result<(),std::io::Error>{
    let mut f = File::open("response_packet.txt")?;
    let mut buffer = BytePacketBuffer::new();
    f.read(&mut buffer.buf)?;

    let packet = DNSPacket::from_buffer(&mut buffer)?;
    println!("{:#?}", packet.header);

    for q in packet.question.questions {
        println!("{:#?}", q);
    }
    for rec in packet.answer.answers {
        println!("{:#?}", rec);
    }
    for rec in packet.authority.records {
        println!("{:#?}", rec);
    }
    for rec in packet.additional.records {
        println!("{:#?}", rec);
    }

    Ok(())
}
