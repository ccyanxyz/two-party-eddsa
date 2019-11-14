extern crate argparse;
extern crate two_party_eddsa_client;
extern crate stopwatch;

use argparse::{ ArgumentParser, StoreTrue, Store };
use two_party_eddsa_client::api::*;
use stopwatch::{ Stopwatch };

fn main() {
    let mut verbose = false;
    let mut net_delay = false;
    let mut keygen = false;
    let mut sign = false;
    let mut msg = "hello world".to_string();

    {
        let mut ap = ArgumentParser::new();
        ap.set_description("two party eddsa client");
        ap.refer(&mut verbose)
            .add_option(&["-v", "--verbose"], StoreTrue, "verbose");
        ap.refer(&mut keygen)
            .add_option(&["-g", "--keygen"], StoreTrue, "keygen");
        ap.refer(&mut sign)
            .add_option(&["-s", "--sign"], StoreTrue, "sign");
        ap.refer(&mut msg)
            .add_option(&["-m", "--msg"], Store, "msg to sign");
        ap.refer(&mut net_delay)
            .add_option(&["-d", "--delay"], StoreTrue, "get network delay");
        ap.parse_args_or_exit();
    }


    if keygen {
        fn_keygen();
    }

    if sign {
        fn_sign(msg);
    }

    if net_delay {
        get_delay();
    }
}

fn get_delay() {
    let client_shim = ClientShim::new("http://localhost:8000".to_string());
    let sw = Stopwatch::start_new();
    two_party_eddsa_client::api::net_delay(&client_shim);
    let t = sw.elapsed_ms();
    println!("network delay: {} ms", t);
}

fn fn_keygen() {
    let client_shim = ClientShim::new("http://localhost:8000".to_string());
    let sw = Stopwatch::start_new();

    let (keypair, keyagg, id) = two_party_eddsa_client::api::generate_key(&client_shim).unwrap();
    let t = sw.elapsed_ms();
    
    println!("keypair: {:?}", keypair);
    println!("keyagg: {:?}", keyagg);
    println!("id: {:?}", id);
    println!("elapsed time: {} ms", t);
}

fn fn_sign(msg: String) {
    let client_shim = ClientShim::new("http://localhost:8000".to_string());
    let (keypair, keyagg, id) = two_party_eddsa_client::api::generate_key(&client_shim).unwrap();
    
    let strs: Vec<String> = msg.as_bytes().iter()
        .map(|b| format!("{:02X}", b)).collect();
    let msg = strs.join("");
    let msg = BigInt::from_hex(&msg);

    let sw = Stopwatch::start_new();
    let signature = two_party_eddsa_client::api::sign(&client_shim, msg, &keypair, &keyagg, &id).expect("error while signing");
    let t = sw.elapsed_ms();

    println!("sig: {:?}", signature);
    println!("elapsed time: {} ms", t);
}
