use rocket;
use rocket::{Request, Rocket};
use rocksdb;

use super::routes::eddsa;


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
    let db_config = eddsa::Config {
        db: rocksdb::DB::open_default("./db").unwrap(),
    };

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
        .manage(db_config)
}