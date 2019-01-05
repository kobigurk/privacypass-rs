#[macro_use]
extern crate log;

extern crate privacypass_rs;

use privacypass_rs::server::*;
use privacypass_rs::db;

use std::net::{TcpStream, TcpListener};
use std::io::{Read, Write};
use std::fs;
use std::error::Error;

use std::collections::HashMap;
use rand::Rng;

fn handle_client<R: Rng>(stream: &mut TcpStream, processor: &mut ServerProcessor, rng: &mut R) -> Result<(), Box<Error>> {
    let mut buf = vec![0; 10*1024*1024];
    loop {
        let n = stream.read(&mut buf)?;
        let msg = &buf[..n];
        let response_str = processor.process_server_message(&msg, rng)?;
        debug!("response_str: {}", response_str);
        stream.write(&response_str.as_bytes())?;
        stream.flush()?;
    }
}

fn run_server(dal: &mut db::DAL) -> Result<(), Box<Error>> {
    env_logger::try_init()?;
    let settings : ServerSettings = ServerSettings::new("server_settings.yaml")?;
    let contents = fs::read_to_string(settings.secret_key_path)?;

    let secret_key_pem = openssl::pkey::PKey::private_key_from_pem(&contents.into_bytes())?;
    let secret_key_bytes = secret_key_pem.ec_key()?.private_key().to_vec();

    let listener = TcpListener::bind(settings.listen_address)?;

    let commitment_struct : HashMap<String, String> = serde_json::from_str(&fs::read_to_string(settings.commitment_path)?)?;

    let mut rng = rand::thread_rng();
    let mut processor = ServerProcessor::new(&secret_key_bytes, &base64::decode(&commitment_struct["G"])?, dal)?;
    // accept connections and process them serially
    for stream in listener.incoming() {
        match handle_client(&mut stream?, &mut processor, &mut rng) {
            Ok(()) => println!("stream finished successfully."),
            Err(e) => println!("error occured: {}", e),
        };
    }

    Ok(())
}

fn main() {
    let mut dal = match db::DAL::new("tokens_server.db") {
        Ok(d) => d,
        Err(e) => {
            println!("error: {}\n", e);
            std::process::exit(1);
        }
    };

    match run_server(&mut dal) {
        Ok(()) => println!("server finished successfully."),
        Err(e) => println!("error running server: {}", e),
    }
}
