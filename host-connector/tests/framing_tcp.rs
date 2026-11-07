//! Task 4.3 acceptance: two ISO 8583 messages sent back-to-back over a real TCP socket arrive merged in the
//! byte stream, and the receiving host still parses them as two separate transactions.

use std::io::{self, Read};
use std::net::{TcpListener, TcpStream};
use std::thread;

use host_connector::framing::{Framing, LengthHeader};
use iso8583::{pack, unpack, Dictionary, Iso8583Message};

fn dialect() -> Dictionary {
    Dictionary::from_json(include_str!("../../iso8583/dialects/synthetic-host.json")).unwrap()
}

fn echo(stan: &str) -> Vec<u8> {
    let mut msg = Iso8583Message::new("0800").unwrap();
    msg.set(7, &b"1107102000"[..]).unwrap();
    msg.set(11, stan.as_bytes()).unwrap();
    msg.set(70, &b"301"[..]).unwrap();
    pack(&msg, &dialect()).unwrap()
}

/// What a host does: read frames until the connection closes, parse each, report MTI and STAN.
fn host_reads_all(framing: Framing, stream: &mut impl Read) -> Vec<(String, String)> {
    let d = dialect();
    let mut seen = Vec::new();
    loop {
        match framing.read_frame(stream) {
            Ok(frame) => {
                let msg = unpack(&frame, &d).expect("each frame is exactly one ISO 8583 message");
                seen.push((msg.mti().to_owned(), msg.get_str(11).unwrap().to_owned()));
            }
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return seen,
            Err(e) => panic!("{e}"),
        }
    }
}

#[test]
fn two_messages_sent_back_to_back_are_parsed_separately() {
    for header in [LengthHeader::Binary2, LengthHeader::Ascii4] {
        let framing = Framing::new(header);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let host = thread::spawn(move || host_reads_all(framing, &mut listener.accept().unwrap().0));

        // Both frames go out in a single write, so they are guaranteed to be adjacent in the stream.
        let mut both = Vec::new();
        framing.encode(&echo("000001"), &mut both).unwrap();
        framing.encode(&echo("000002"), &mut both).unwrap();
        io::Write::write_all(&mut TcpStream::connect(addr).unwrap(), &both).unwrap(); // dropped: closes

        assert_eq!(host.join().unwrap(), [("0800".into(), "000001".into()), ("0800".into(), "000002".into())],
                   "{header:?}");
    }
}

/// A stream that hands out one byte per read, the worst case TCP is allowed to produce.
struct Trickle<'a>(&'a [u8]);

impl Read for Trickle<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let Some((&first, rest)) = self.0.split_first() else { return Ok(0) };
        if buf.is_empty() {
            return Ok(0);
        }
        buf[0] = first;
        self.0 = rest;
        Ok(1)
    }
}

#[test]
fn messages_split_across_many_reads_still_arrive_whole() {
    let framing = Framing::new(LengthHeader::Binary2);
    let mut stream = Vec::new();
    for stan in ["000001", "000002", "000003"] {
        framing.encode(&echo(stan), &mut stream).unwrap();
    }
    let seen = host_reads_all(framing, &mut Trickle(&stream));
    assert_eq!(seen.iter().map(|(_, stan)| stan.as_str()).collect::<Vec<_>>(), ["000001", "000002", "000003"]);
}
