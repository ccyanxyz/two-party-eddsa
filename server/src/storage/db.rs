use super::super::routes::eddsa;
use super::super::Result;
use rocksdb::DB;
use serde;

fn idify(id: &str, struct_name: &eddsa::MPCStruct) -> String {
    format!("{:?}_{:?}", id, struct_name)
}

pub fn insert<T>(db: &DB, id: &str, struct_name: &eddsa::MPCStruct, v: T) -> Result<()>
    where
        T: serde::ser::Serialize,
{
    let identifier = idify(id, struct_name);
    let v_string = serde_json::to_string(&v).unwrap();
    db.put(identifier.as_ref(), v_string.as_ref())?;
    Ok(())
}

pub fn get<T>(db: &DB, id: &str, struct_name: &eddsa::MPCStruct) -> Result<Option<T>>
    where
        T: serde::de::DeserializeOwned,
{
    let identifier = idify(id, struct_name);
    info!("Getting from db ({})", identifier);

    match db.get(identifier.as_ref()) {
        Ok(Some(value)) => {
            let vec: Vec<u8> = value.to_vec();
            Ok(serde_json::from_slice(&vec).unwrap())
        },
        Ok(None) => Ok(None),  // value not found
        Err(e) => Err(format_err!("{}", e.to_string()))  // operational error
    }
}
