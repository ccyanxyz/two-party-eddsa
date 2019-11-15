use std::{ fs, io };
use std::io::prelude::*;
use std::io::Read;
use std::fs::OpenOptions;
use std::fs::File;
use std::path::Path;

use super::super::routes::eddsa;
use super::super::Result;
use serde;

fn idify(id: &str, struct_name: &eddsa::MPCStruct) -> String {
    format!("{:?}_{:?}", id, struct_name)
}

pub fn mkdir(path: &str) -> io::Result<()> {
    match Path::new(path).exists() {
        true => Ok(()),
        false => fs::create_dir(path),
    }
}

pub fn insert<T>(filepath: &str, id: &str, struct_name: &eddsa::MPCStruct, v: T) -> Result<()>
    where
        T: serde::ser::Serialize,
{
    let identifier = idify(id, struct_name);
    let identifier = format!("{}/{}", filepath, identifier);

    let v_string = serde_json::to_string(&v).unwrap();
    
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .append(true)
        .open(identifier);
    
    match file {
        Ok(mut stream) => {
            match stream.write_all(v_string.as_bytes()) {
                Ok(_) => Ok(()),
                Err(e) => Err(format_err!("{}", e.to_string()))
            }
        },
        Err(err) => {
            Err(format_err!("{}", err.to_string()))
        }
    }
}

pub fn get<T>(filepath: &str, id: &str, struct_name: &eddsa::MPCStruct) -> Result<Option<T>>
    where
        T: serde::de::DeserializeOwned,
{
    let identifier = idify(id, struct_name);
    let identifier = format!("{}/{}", filepath, identifier);
    info!("reading ({})", identifier);

    let mut file = File::open(&identifier)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    Ok(serde_json::from_slice(&data).unwrap())
}
