use std::io::prelude::*;
use std::io::{ Read, Write };
use std::fs::File;
use std::vec::Vec;

use super::eddsa::*;

pub fn save_keyfile(filepath: &str, keypair: KeyPair, keyagg: KeyAgg) {
    // store keys to keyfile
    // pubkey(32 bytes) + privkey_prefix(32 bytes) + privkey(32 bytes) + key_agg_point(32 bytes) + key_agg_hash(32 bytes)
    let mut buf = vec![];
    buf.append(&mut keypair.public_key.get_element().to_bytes().to_vec());
    buf.append(&mut keypair.expended_private_key.prefix.get_element().to_bytes().to_vec());
    buf.append(&mut keypair.expended_private_key.private_key.get_element().to_bytes().to_vec());
    buf.append(&mut keyagg.apk.get_element().to_bytes().to_vec());
    buf.append(&mut keyagg.hash.get_element().to_bytes().to_vec());
    let mut file = File::create(&filepath).expect("create failed");
    file.write_all(buf.as_slice()).expect("write failed");
}

pub fn load_keyfile(filepath: &str) -> (KeyPair, KeyAgg) {
    // read keyfile
    let mut buf = Vec::new();
    let mut file = File::open(&filepath).unwrap();
    file.read_to_end(&mut buf);

    let eight: FE = ECScalar::from(&BigInt::from(8));
    let eight_inverse: FE = eight.invert();

    let pubkey = GE::from_bytes(&buf[0..32]).unwrap();
    let pubkey = pubkey * &eight_inverse;

    let t = &mut buf[32..64];
    t.reverse();
    let privkey_prefix: FE = ECScalar::from(&BigInt::from(&t[0..32]));
    let t = &mut buf[64..96];
    t.reverse();
    let privkey: FE = ECScalar::from(&BigInt::from(&t[0..32]));

    let keypair = KeyPair {
        public_key: pubkey,
        expended_private_key: ExpendedPrivateKey {
            prefix: privkey_prefix,
            private_key: privkey,
        }
    };

    let agg_pubkey = GE::from_bytes(&buf[96..128]).unwrap();
    let agg_pubkey = agg_pubkey * &eight_inverse;
    let t = &mut buf[128..160];
    t.reverse();
    let agg_pubkey_hash: FE = ECScalar::from(&BigInt::from(&t[0..32]));

    let key_agg = KeyAgg {
        apk: agg_pubkey,
        hash: agg_pubkey_hash,
    };
    (keypair, key_agg)
}

pub fn str_to_bigint(msg: String) -> BigInt {
    let strs: Vec<String> = msg.as_bytes()
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect();
    let msg = strs.join("");
    BigInt::from_hex(&msg)
}

pub fn bigint_to_bytes(num: BigInt) -> [u8; 32] {
    [0u8; 32] 
}
