extern crate argparse;
extern crate stopwatch;

use std::io::prelude::*;
use std::io::{ Read, Write };
use std::net::TcpStream;
use std::str::from_utf8;
use std::vec::Vec;
use std::fs::File;
use std::fs::OpenOptions;

use argparse::{ ArgumentParser, StoreTrue, Store };
use stopwatch::{ Stopwatch };

mod eddsa;
use eddsa::*;
mod util;
use util::*;

const host: &str = "127.0.0.1:8000";

fn main() {
    let mut verbose = false;
    let mut net_delay = false;
    let mut keygen = false;
    let mut keyfile = "client.key".to_string();
    let mut sign = false;
    let mut verify = false;
    let mut msg = "hello world".to_string();
    {
        let mut ap = ArgumentParser::new();
        ap.set_description("two party eddsa client");
        ap.refer(&mut verbose)
            .add_option(&["-v", "--verbose"], StoreTrue, "verbose");
        ap.refer(&mut keygen)
            .add_option(&["-g", "--keygen"], StoreTrue, "keygen");
        ap.refer(&mut keyfile)
            .add_option(&["-k", "--keyfile"], Store, "keyfile");
        ap.refer(&mut sign)
            .add_option(&["-s", "--sign"], StoreTrue, "sign");
        ap.refer(&mut msg)
            .add_option(&["-m", "--msg"], Store, "msg to sign");
        ap.refer(&mut net_delay)
            .add_option(&["-d", "--delay"], StoreTrue, "get network delay");
        ap.parse_args_or_exit();
    }

    if keygen {
        let sw = Stopwatch::start_new();
        fn_keygen(&keyfile);
        println!("elapsed_time: {} ms", sw.elapsed_ms());
    }
    if sign {
        let sw = Stopwatch::start_new();
        fn_sign(msg, &keyfile);
        println!("elapsed_time: {} ms", sw.elapsed_ms());
    }
    if net_delay {
        let sw = Stopwatch::start_new();
        fn_delay();
        println!("elapsed_time: {} ms", sw.elapsed_ms());
    }
}

fn fn_keygen(keyfile: &String) {
    let mut stream = TcpStream::connect(host).unwrap();
    let client_keypair: KeyPair = KeyPair::create();

    println!("{:?}", client_keypair);

    let mut buf = vec![1u8];
    let mut client_pubkey = client_keypair.public_key.get_element().to_bytes().to_vec();
    buf.append(&mut client_pubkey);

    stream.write(buf.as_slice()).unwrap();

    let mut buf = [0u8; 32];
    stream.read(&mut buf).unwrap();
    let server_pubkey = GE::from_bytes(&buf).unwrap();
    let eight: FE = ECScalar::from(&BigInt::from(8));
    let eight_inverse: FE = eight.invert();
    let server_pubkey = server_pubkey * &eight_inverse;
    println!("server_pubkey: {:?}", server_pubkey);

    // calc aggregated pubkey
    let mut pks: Vec<GE> = Vec::new();
    pks.push(server_pubkey.clone());
    pks.push(client_keypair.public_key.clone());
    let key_agg = KeyPair::key_aggregation_n(&pks, &1);
    println!("aggregated_pubkey: {:?}", key_agg);

    save_keyfile(keyfile, client_keypair, key_agg);
}

fn fn_sign(msg: String, keyfile: &String) {
    let (client_keypair, key_agg) = load_keyfile(keyfile);

    println!("client_keypair: {:?}", client_keypair);
    println!("key_agg: {:?}", key_agg);

    let mut stream = TcpStream::connect(host).unwrap();
    // round 1
    let msg = str_to_bigint(msg);
    println!("msg: {:?}", msg);
    let (client_ephemeral_key, client_sign_first_msg, client_sign_second_msg) = Signature::create_ephemeral_key_and_commit(&client_keypair, BigInt::to_vec(&msg).as_slice());
    println!("client_sign_first_msg: {:?}", client_sign_first_msg);

    let mut buf = vec![2u8];
    buf.append(&mut Converter::to_vec(&client_sign_first_msg.commitment));
    buf.append(&mut Converter::to_vec(&msg));
    stream.write(buf.as_slice()).unwrap();

    let mut buf = [0u8; 32];
    stream.read(&mut buf).unwrap();
    let server_sign_first_msg = SignFirstMsg {
        commitment: BigInt::from(&buf[0..32]),
    };
    println!("server_sign_first_msg: {:?}", server_sign_first_msg);

    // round 2
    println!("client_sign_second_msg: {:?}", client_sign_second_msg);
    let mut buf: Vec<u8> = Vec::new(); 
    buf.append(&mut client_sign_second_msg.R.get_element().to_bytes().to_vec());
    buf.append(&mut Converter::to_vec(&client_sign_second_msg.blind_factor));
    stream.write(buf.as_slice());

    // R:GE, blind_factor, R:GE, s:FE;
    let mut buf = vec![0u8; 128];
    stream.read(&mut buf);

    let eight: FE = ECScalar::from(&BigInt::from(8));
    let eight_inverse: FE = eight.invert();

    let server_sign_second_msg_R = GE::from_bytes(&buf[0..32]).unwrap();
    let server_sign_second_msg_R = server_sign_second_msg_R * &eight_inverse;
    let server_sign_second_msg_bf = BigInt::from(&buf[32..64]);
    let server_sig_R = GE::from_bytes(&buf[64..96]).unwrap();
    let server_sig_R = server_sig_R * &eight_inverse;
    let t = &mut buf[96..128];
    t.reverse();
    let server_sig_s: FE = ECScalar::from(&BigInt::from(&t[0..32]));
    let server_sign_second_msg = SignSecondMsg {
        R: server_sign_second_msg_R,
        blind_factor: server_sign_second_msg_bf,
    };
    let server_sig = Signature {
        R: server_sig_R,
        s: server_sig_s,
    };

    // check commitment
    assert!(test_com(
        &server_sign_second_msg.R,
        &server_sign_second_msg.blind_factor,
        &server_sign_first_msg.commitment
    ));

    // round 3
    let mut ri: Vec<GE> = Vec::new();
    ri.push(server_sign_second_msg_R.clone());
    ri.push(client_sign_second_msg.R.clone());
    let r_tot = Signature::get_R_tot(ri);
    let k = Signature::k(&r_tot, &key_agg.apk, BigInt::to_vec(&msg).as_slice());
    let s2 = Signature::partial_sign(
        &client_ephemeral_key.r,
        &client_keypair,
        &k,
        &key_agg.hash,
        &r_tot,
    );
    
    let mut s: Vec<Signature> = Vec::new();
    s.push(server_sig);
    s.push(s2);
    let sig = Signature::add_signature_parts(s);

    println!("sig: {:?}", sig);

    // verify
    verify(&sig, BigInt::to_vec(&msg).as_slice(), &key_agg.apk);
}

fn fn_delay() {
    let mut stream = TcpStream::connect(host).unwrap();
    let msg = "hello world".to_string();
    let mut buf = vec![4u8];
    buf.append(&mut msg.as_bytes().to_vec());

    stream.write(buf.as_slice()).unwrap();
    stream.read(&mut buf).unwrap();
}

fn str_to_bigint(msg: String) -> BigInt {
    let strs: Vec<String> = msg.as_bytes()
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect();
    let msg = strs.join("");
    println!("msg_hex: {:?}", msg);
    BigInt::from_hex(&msg)
}
