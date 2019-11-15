use std::io;
use std::thread;
use std::str::from_utf8;
use std::net::{ TcpListener, TcpStream };
use std::io::{ Read, Write };

extern crate rustc_serialize;
use rustc_serialize::hex::ToHex;

mod eddsa;
use eddsa::*;
mod util;
use util::*;

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
    let mut buf = [0u8; 200];
    let len = stream.read(&mut buf).unwrap();
    match buf[0] {
        1 => {
            println!("keygen");
            keygen(&mut stream, &mut buf);
        },
        2 => {
            println!("sign_first");
            sign(&mut stream, &mut buf, len);
        },
        4 => {
            println!("test network delay");
            stream.write(b"hello back").unwrap();
        }
        _ => {  },
    }

    Ok(())
}

fn keygen(stream: &mut TcpStream, buf: &mut [u8; 200]) {
    let client_pubkey = GE::from_bytes(&buf[1..33]).unwrap(); 
    let eight: FE = ECScalar::from(&BigInt::from(8));
    let eight_inverse: FE = eight.invert();
    let client_pubkey = client_pubkey * &eight_inverse;
    println!("client_pubkey: {:?}", client_pubkey);

    let server_keypair = KeyPair::create();
    println!("server_keypair: {:?}", server_keypair);
    let server_pubkey = server_keypair.public_key.get_element().to_bytes();
    stream.write(&server_pubkey).unwrap();

    // calc agg pubkey
    let mut pks: Vec<GE> = Vec::new();
    pks.push(server_keypair.public_key.clone());
    pks.push(client_pubkey.clone());
    let key_agg = KeyPair::key_aggregation_n(&pks, &0);
    println!("aggregated_pubkey: {:?}", key_agg);

    save_keyfile("server.key", server_keypair, key_agg);
}

fn sign(stream: &mut TcpStream, buf: &mut [u8; 200], len: usize) {
    let (server_keypair, key_agg) = load_keyfile("server.key");
    
    let client_commitment = BigInt::from(&buf[1..33]);
    let msg = BigInt::from(&buf[33..len]);

    println!("client_commitment: {:?}", client_commitment);
    println!("msg: {:?}", msg);

    let (server_ephemeral_key, server_sign_first_msg, server_sign_second_msg) = Signature::create_ephemeral_key_and_commit(&server_keypair, BigInt::to_vec(&msg).as_slice());
    println!("server_sign_first_msg: {:?}", server_sign_first_msg);

    stream.write(&mut Converter::to_vec(&server_sign_first_msg.commitment));

    // sign second
    let mut buf = [0u8; 64];
    stream.read(&mut buf);
    let eight: FE = ECScalar::from(&BigInt::from(8));
    let eight_inverse: FE = eight.invert();
    let client_sign_second_msg_R = GE::from_bytes(&buf[0..32]).unwrap();
    let client_sign_second_msg_R = client_sign_second_msg_R * &eight_inverse;
    let client_sign_second_msg_bf = BigInt::from(&buf[32..64]);

    // check commitment
    assert!(test_com(
        &client_sign_second_msg_R,
        &client_sign_second_msg_bf,
        &client_commitment,
    ));

    let mut ri: Vec<GE> = Vec::new();
    ri.push(server_sign_second_msg.R.clone());
    ri.push(client_sign_second_msg_R.clone());
    let r_tot = Signature::get_R_tot(ri);
    let k = Signature::k(&r_tot, &key_agg.apk, &BigInt::to_vec(&msg).as_slice());
    let s1 = Signature::partial_sign(
        &server_ephemeral_key.r,
        &server_keypair,
        &k,
        &key_agg.hash,
        &r_tot,
    );

    let mut buf: Vec<u8> = Vec::new();
    buf.append(&mut server_sign_second_msg.R.get_element().to_bytes().to_vec());
    buf.append(&mut Converter::to_vec(&server_sign_second_msg.blind_factor));
    buf.append(&mut s1.R.get_element().to_bytes().to_vec());
    buf.append(&mut s1.s.get_element().to_bytes().to_vec());
    stream.write(buf.as_slice());
}
