extern crate argparse;
extern crate stopwatch;

mod two_party_eddsa;

use std::io::{ Read, Write };
use std::net::TcpStream;
use std::str::from_utf8;

use argparse::{ ArgumentParser, StoreTrue, Store };
use stopwatch::{ Stopwatch };

const host: &str = "127.0.0.1:8000";

fn main() {
    let mut verbose = false;
    let mut net_delay = false;
    let mut keygen = false;
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
        fn_delay();
    }
}

fn fn_keygen() {
    let mut stream = TcpStream::connect(host).unwrap();
    let client_keypair: KeyPair = KeyPair::create();

    println!("{:?}", client_keypair);
}

fn fn_sign(msg: String) {

}

fn fn_delay() {

}
