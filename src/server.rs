use std::io;
use std::thread;
use std::str::from_utf8;
use std::net::{ TcpListener, TcpStream };
use std::io::{ Read, Write };

fn main() {
    let host = "0.0.0.0:8000";

    let listener = TcpListener::bind(host).unwrap();
    for stream in listener.incoming() {
        match stream {
            Err(e) => println!("Accept err {}", e),
            Ok(stream) => {
                thread::spawn(move || {
                    println!("{:?}", handle_client(stream).unwrap());
                });
            }
        }
    }
    drop(listener);
}

fn handle_client(mut stream: TcpStream) -> io::Result<()> {
    println!("new client-> {:?}", stream.peer_addr().unwrap());
    let mut buf = [0u8; 4096];
    loop {
        let got = try!(stream.read(&mut buf));
        if got == 0 {
            break
        }
        //try!(stream.write(&buf[0..got]));

        let op = buf[0];
        match op {
            0 => {
                println!("keygen, client pubkey: {}", from_utf8(buf[1..got]).unwrap());
            },
            1 => {
                println!("sign_first: client commitment: {}", from_utf8(buf[1..got]).unwrap());
            },
            2 => {
                println!("sign_second: client (R, r): {}", from_utf8(buf[1..got]).unwrap());
            }
        }
    }
    Ok(())
}
