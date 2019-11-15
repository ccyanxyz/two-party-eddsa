extern crate curv;
extern crate hex;

#[macro_use]
extern crate serde_derive;
extern crate serde_json;

pub mod eddsa;

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum Error {
    InvalidKey,
    InvalidSS,
    InvalidCom,
    InvalidSig,
}

use std::fmt;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &self)
    }
}

impl std::error::Error for Error {  }
