use rocket;
use rocket::{Request, Rocket};
use rocksdb;

use super::routes::eddsa;
use super::storage::file;

#[catch(500)]
fn internal_error() -> &'static str {
    "Internal server error"
}

#[catch(400)]
fn bad_request() -> &'static str {
    "Bad request"
}

#[catch(404)]
fn not_found(req: &Request) -> String {
    format!("Unknown route '{}'.", req.uri())
}

pub fn get_server() -> Rocket {
    let storage_config = eddsa::Config {
        db: rocksdb::DB::open_default("./db").unwrap(),
        filepath: "temp".to_string(),
    };
    
    file::mkdir("temp");

    rocket::ignite()
        .register(catchers![internal_error, not_found, bad_request])
        .mount(
            "/",
            routes![
                eddsa::keygen,
                eddsa::sign_first,
                eddsa::sign_second,
            ],
        )
        .manage(storage_config)
}
