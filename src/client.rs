#![allow(non_snake_case)]
extern crate argparse;
extern crate stopwatch;

use std::io::{ Read, Write };
use std::net::TcpStream;
use std::vec::Vec;

use argparse::{ ArgumentParser, StoreTrue, Store };
use stopwatch::{ Stopwatch };

use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::Hash;

extern crate rustc_serialize;
use rustc_serialize::hex::ToHex;
extern crate hex;

mod eddsa;
use eddsa::*;
mod util;
use util::*;

fn main() {
    let mut host = "127.0.0.1:8000".to_string();
    let mut net_delay = false;
    let mut keygen = false;
    let mut keyfile = "client.key".to_string();
    let mut sign = false;
    let mut verify = false;
    let mut r = "".to_string();
    let mut s = "".to_string();
    let mut pubkey = "".to_string();
    let mut msg = "hello world".to_string();
    let mut bench_gen = 0;
    let mut bench_sign = 0;
    {
        let mut ap = ArgumentParser::new();
        ap.set_description("two-party-eddsa client");
        ap.refer(&mut host)
            .add_option(&["-h", "--host"], Store, "server address:port");
        ap.refer(&mut verify)
            .add_option(&["-v", "--verify"], StoreTrue, "verify");
        ap.refer(&mut r)
            .add_option(&["--sig-r"], Store, "R");
        ap.refer(&mut s)
            .add_option(&["--sig-s"], Store, "s");
        ap.refer(&mut pubkey)
            .add_option(&["--pubkey"], Store, "aggrageted pubkey");
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
        ap.refer(&mut bench_gen)
            .add_option(&["--bench-gen"], Store, "bench keygen");
        ap.refer(&mut bench_sign)
            .add_option(&["--bench-sign"], Store, "bench sign");
        ap.parse_args_or_exit();
    }

    if keygen {
        let sw = Stopwatch::start_new();
        let mut stream = TcpStream::connect(&host).unwrap();
        fn_keygen(&mut stream, &keyfile);
        println!("elapsed_time: {} ms", sw.elapsed_ms());
    }
    if sign {
        let sw = Stopwatch::start_new();
        let mut stream = TcpStream::connect(&host).unwrap();
        fn_sign(&mut stream, &msg, &keyfile);
        println!("elapsed_time: {} ms", sw.elapsed_ms());
    }
    if verify {
        let sw = Stopwatch::start_new();
        fn_verify(&msg, &r, &s, &pubkey);
        println!("elapsed_time: {} ms", sw.elapsed_ms());
    }
    if net_delay {
        let sw = Stopwatch::start_new();
        let mut stream = TcpStream::connect(&host).unwrap();
        fn_delay(&mut stream);
        println!("elapsed_time: {} ms", sw.elapsed_ms());
    }
    if bench_gen != 0 {
        let sw = Stopwatch::start_new();
        for _ in 0..bench_gen {
            let mut temps = TcpStream::connect(&host).unwrap();
            fn_keygen(&mut temps, &keyfile);
        }
        let t = sw.elapsed_ms();
        let per_key: f64 = t as f64 / bench_gen as f64;
        println!("bench keygen: {} keys in {} ms, {} ms per key", bench_gen, t, per_key);
    }
    if bench_sign != 0 {
        let sw = Stopwatch::start_new();
        for _ in 0..bench_sign {
            let mut temps = TcpStream::connect(&host).unwrap();
            fn_sign(&mut temps, &msg, &keyfile);
        }
        let t = sw.elapsed_ms();
        let per_sign: f64 = t as f64 / bench_sign as f64;
        println!("bench sign: {} signs in {} ms, {} ms per sign", bench_sign, t, per_sign);
    }
}

fn fn_keygen(stream: &mut TcpStream, keyfile: &String) {
    let client_keypair: KeyPair = KeyPair::create();

    //println!("{:?}", client_keypair);

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
    //println!("server_pubkey: {:?}", server_pubkey);

    // calc aggregated pubkey
    let mut pks: Vec<GE> = Vec::new();
    pks.push(server_pubkey.clone());
    pks.push(client_keypair.public_key.clone());
    let key_agg = KeyPair::key_aggregation_n(&pks, &1);
    println!("aggregated_pubkey: {:?}", key_agg.apk.get_element().to_bytes().to_hex());

    save_keyfile(keyfile, client_keypair, key_agg);
}

fn fn_sign(stream: &mut TcpStream, msg: &str, keyfile: &String) {
    let (client_keypair, key_agg) = load_keyfile(keyfile).unwrap();

    //println!("client_keypair: {:?}", client_keypair);
    //println!("key_agg: {:?}", key_agg);

    // round 1
    let msg = str_to_bigint(msg.to_string());
    let msg_hash = HSha256::create_hash(&vec![&msg]);
    let (client_ephemeral_key, client_sign_first_msg, client_sign_second_msg) = Signature::create_ephemeral_key_and_commit(&client_keypair, BigInt::to_vec(&msg_hash).as_slice());
    //println!("client_sign_first_msg: {:?}", client_sign_first_msg);

    let mut buf = vec![2u8];
    buf.append(&mut bigint_to_bytes32(&client_sign_first_msg.commitment).to_vec());
    buf.append(&mut bigint_to_bytes32(&msg_hash).to_vec());
    buf.append(&mut client_keypair.public_key.get_element().to_bytes().to_vec());
    stream.write(buf.as_slice()).unwrap();

    let mut buf = [0u8; 32];
    stream.read(&mut buf).unwrap();
    let server_sign_first_msg = SignFirstMsg {
        commitment: BigInt::from(&buf[0..32]),
    };
    //println!("server_sign_first_msg: {:?}", server_sign_first_msg);

    // round 2
    //println!("client_sign_second_msg: {:?}", client_sign_second_msg);
    let mut buf: Vec<u8> = Vec::new(); 
    buf.append(&mut client_sign_second_msg.R.get_element().to_bytes().to_vec());
    buf.append(&mut bigint_to_bytes32(&client_sign_second_msg.blind_factor).to_vec());
    match stream.write(buf.as_slice()) {
        Ok(_) => {  },
        Err(e) => {
            println!("stream write error: {:?}", e);
            return;
        }
    }

    // R:GE, blind_factor, R:GE, s:FE;
    let mut buf = vec![0u8; 128];
    match stream.read(&mut buf) {
        Ok(_) => {  },
        Err(e) => {
            println!("stream read error: {:?}", e);
            return;
        }
    }

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
    let ret = check_commitment(
        &server_sign_second_msg.R,
        &server_sign_second_msg.blind_factor,
        &server_sign_first_msg.commitment
    );

    if ret == false {
        // for debug;
        println!("server_sign_second_msg: {:?}", server_sign_second_msg);
        println!("server_commitment: {:?}", server_sign_first_msg.commitment);
        println!("client_sign_second_msg: {:?}", client_sign_second_msg);
        println!("client_commitment: {:?}", client_sign_first_msg.commitment);
    }
    assert!(ret);

    // round 3
    let mut ri: Vec<GE> = Vec::new();
    ri.push(server_sign_second_msg_R.clone());
    ri.push(client_sign_second_msg.R.clone());
    let r_tot = Signature::get_R_tot(ri);
    let k = Signature::k(&r_tot, &key_agg.apk, BigInt::to_vec(&msg_hash).as_slice());
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

    println!("R: {:?}", sig.R.get_element().to_bytes().to_hex());
    println!("s: {:?}", sig.s.get_element().to_bytes().to_hex());

    // verify
    match verify(&sig, BigInt::to_vec(&msg_hash).as_slice(), &key_agg.apk) {
        Ok(_) => { println!("signature valid"); },
        Err(_) => { println!("signature invalid"); },
    }
}

fn fn_verify(msg: &str, r: &str, s: &str, pubkey: &str) {
    let msg = str_to_bigint(msg.to_string());
    let msg_hash = HSha256::create_hash(&vec![&msg]);
    let r_decode = hex::decode(r).expect("decode r failed");
    let mut s_decode = hex::decode(s).expect("decode s failed");
    s_decode.reverse();
    let pubkey_decode = hex::decode(pubkey).expect("decode pubkey failed");

    let eight: FE = ECScalar::from(&BigInt::from(8));
    let eight_inverse: FE = eight.invert();

    let r = GE::from_bytes(&r_decode).unwrap();
    let r = r * &eight_inverse;
    let s: FE = ECScalar::from(&BigInt::from(&s_decode[0..32]));
    let pubkey = GE::from_bytes(&pubkey_decode).unwrap();
    let pubkey = pubkey * &eight_inverse;
    let sig = Signature {
        R: r,
        s: s,
    };

    match verify(&sig, BigInt::to_vec(&msg_hash).as_slice(), &pubkey) {
        Ok(_) => {
            println!("true");
        },
        Err(err) => {
            println!("false: {:?}", err);
        }
    }
}

fn fn_delay(stream: &mut TcpStream) {
    let msg = "hello world".to_string();
    let mut buf = vec![3u8];
    buf.append(&mut msg.as_bytes().to_vec());

    stream.write(buf.as_slice()).unwrap();
    stream.read(&mut buf).unwrap();
}
