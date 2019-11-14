use super::super::api;
use serde;
use time::PreciseTime;

pub fn postb<T, V>(client_shim: &api::ClientShim, path: &str, body: T) -> Option<V>
    where
        T: serde::ser::Serialize,
        V: serde::de::DeserializeOwned,
{
    let start = PreciseTime::now();

    let b = client_shim
        .client
        .post(&format!("{}/{}", client_shim.endpoint, path));

    let res = b.json(&body).send();

    let end = PreciseTime::now();

    info!("(req {}, took: {})", path, start.to(end));

    let value = res.unwrap().text().unwrap();
    Some(serde_json::from_str(value.as_str()).unwrap())
}