#![allow(non_snake_case)]
use std::io;
use std::thread;
use std::net::{ TcpListener, TcpStream };
use std::io::{ Read, Write };
use std::fs;
use std::path::Path;

use argparse::{ ArgumentParser, Store };

extern crate rustc_serialize;
use rustc_serialize::hex::ToHex;

mod eddsa;
use eddsa::*;
mod util;
use util::*;

fn main() {
    let mut host = "0.0.0.0:".to_string();
    let mut port = "8000".to_string();
    let mut keyfile_path = "server_keys".to_string();

    {
        let mut ap = ArgumentParser::new();
        ap.set_description("two-party-eddsa server");
        ap.refer(&mut port)
            .add_option(&["-p", "--port"], Store, "port");
        ap.refer(&mut keyfile_path)
            .add_option(&["-k", "--keyfile-path"], Store, "keyfile path");
        ap.parse_args_or_exit();
    }

    host.push_str(&port);
    // check keyfile_path
    match Path::new(&keyfile_path).exists() {
        true => {  },
        false => {
            fs::create_dir(&keyfile_path).expect("create keyfile_path failed");
        },
    }

    keyfile_path.push_str("/");

    let listener = TcpListener::bind(&host).unwrap();
    for stream in listener.incoming() {
        match stream {
            Err(e) => println!("Accept err {}", e),
            Ok(stream) => {
                let filepath = keyfile_path.clone();
                thread::spawn(move || {
                    println!("{:?}", handle_client(stream, &filepath).unwrap());
                });
            }
        }
    }
    drop(listener);
}

fn handle_client(mut stream: TcpStream, filepath: &str) -> io::Result<()> {
    //println!("new client-> {:?}", stream.peer_addr().unwrap());
    let mut buf = [0u8; 97];
    stream.read(&mut buf).unwrap();
    match buf[0] {
        1 => {
            println!("keygen");
            keygen(&mut stream, &mut buf, filepath);
        },
        2 => {
            println!("sign");
            sign(&mut stream, &mut buf, filepath);
        },
        3 => {
            println!("test network delay");
            stream.write(b"hello back").unwrap();
        }
        _ => {  },
    }

    Ok(())
}

fn keygen(stream: &mut TcpStream, buf: &mut [u8; 97], filepath: &str) {
    let client_pubkey = GE::from_bytes(&buf[1..33]).unwrap(); 
    let eight: FE = ECScalar::from(&BigInt::from(8));
    let eight_inverse: FE = eight.invert();
    let client_pubkey = client_pubkey * &eight_inverse;
    //println!("client_pubkey: {:?}", client_pubkey);

    let server_keypair = KeyPair::create();
    //println!("server_keypair: {:?}", server_keypair);
    let server_pubkey = server_keypair.public_key.get_element().to_bytes();
    stream.write(&server_pubkey).unwrap();

    // calc agg pubkey
    let mut pks: Vec<GE> = Vec::new();
    pks.push(server_keypair.public_key.clone());
    pks.push(client_pubkey.clone());
    let key_agg = KeyPair::key_aggregation_n(&pks, &0);
    //println!("aggregated_pubkey: {:?}", key_agg);

    let id = client_pubkey.get_element().to_bytes().to_hex();
    let mut keyfile = filepath.to_string();
    keyfile.push_str(&id);
    save_keyfile(&keyfile, server_keypair, key_agg);
}

fn sign(stream: &mut TcpStream, buf: &mut [u8; 97], filepath: &str) {
    
    let client_commitment = BigInt::from(&buf[1..33]);
    let msg_hash = BigInt::from(&buf[33..65]);

    //println!("client_commitment: {:?}", client_commitment);
    //println!("msg: {:?}", msg);
    let eight: FE = ECScalar::from(&BigInt::from(8));
    let eight_inverse: FE = eight.invert();

    let client_pubkey = GE::from_bytes(&buf[65..97]).unwrap();
    let client_pubkey = client_pubkey * &eight_inverse;
    let mut keyfile = filepath.to_string();
    let id = client_pubkey.get_element().to_bytes().to_hex();
    keyfile.push_str(&id);
    let (server_keypair, key_agg) = load_keyfile(&keyfile).unwrap();

    let (server_ephemeral_key, server_sign_first_msg, server_sign_second_msg) = Signature::create_ephemeral_key_and_commit(&server_keypair, BigInt::to_vec(&msg_hash).as_slice());
    //println!("server_sign_first_msg: {:?}", server_sign_first_msg);

    match stream.write(&mut bigint_to_bytes32(&server_sign_first_msg.commitment).to_vec()) {
        Ok(_) => {  },
        Err(e) => {
            println!("stream write error: {:?}", e);
        }
    }

    // sign second
    let mut buf = [0u8; 64];
    match stream.read(&mut buf) {
        Ok(_) => {  },
        Err(e) => {
            println!("stream read error: {:?}", e);
        }
    }

    let client_sign_second_msg_R = GE::from_bytes(&buf[0..32]).unwrap();
    let client_sign_second_msg_R = client_sign_second_msg_R * &eight_inverse;
    let client_sign_second_msg_bf = BigInt::from(&buf[32..64]);

    // check commitment
    let ret = check_commitment(
        &client_sign_second_msg_R,
        &client_sign_second_msg_bf,
        &client_commitment,
    );

    if ret == false {
        // for debug
        let client_sign_second_msg = SignSecondMsg {
            R: client_sign_second_msg_R,
            blind_factor: client_sign_second_msg_bf,
        };
        println!("client_sign_second_msg: {:?}", client_sign_second_msg);
        println!("client_commitment: {:?}", client_commitment);
        println!("server_sign_second_msg: {:?}", server_sign_second_msg);
        println!("server_commitment: {:?}", server_sign_first_msg.commitment);
    }
    assert!(ret);

    let mut ri: Vec<GE> = Vec::new();
    ri.push(server_sign_second_msg.R.clone());
    ri.push(client_sign_second_msg_R.clone());
    let r_tot = Signature::get_R_tot(ri);
    let k = Signature::k(&r_tot, &key_agg.apk, &BigInt::to_vec(&msg_hash).as_slice());
    let s1 = Signature::partial_sign(
        &server_ephemeral_key.r,
        &server_keypair,
        &k,
        &key_agg.hash,
        &r_tot,
    );

    let mut buf: Vec<u8> = Vec::new();
    buf.append(&mut server_sign_second_msg.R.get_element().to_bytes().to_vec());
    buf.append(&mut bigint_to_bytes32(&server_sign_second_msg.blind_factor).to_vec());
    buf.append(&mut s1.R.get_element().to_bytes().to_vec());
    buf.append(&mut s1.s.get_element().to_bytes().to_vec());
    match stream.write(buf.as_slice()) {
        Ok(_) => {  },
        Err(e) => {
            println!("stream write error: {:?}", e);
        }
    }
}
