#[macro_use]
extern crate log;

extern crate privacypass_rs;

use privacypass_rs::client::*;
use privacypass_rs::types::{self, curve::big};
use privacypass_rs::ecc;
use privacypass_rs::converters;
use privacypass_rs::net;
use privacypass_rs::db;

use std::error::Error;
use std::collections::HashMap;
use std::fs;

fn parse_batch_proof(batch_proof_str: &[u8]) -> Result<(types::curve::big::BIG, types::curve::big::BIG), Box<Error>> {
  let batch_proof_struct : HashMap<String, String> =
                           serde_json::from_slice(&batch_proof_str)?;
  let proof_struct : HashMap<String, String> = serde_json::from_slice(&base64::decode(&batch_proof_struct["P"])?)?;
  let s = converters::big_from_bytes(&base64::decode(&proof_struct["R"])?);
  let c = converters::big_from_bytes(&base64::decode(&proof_struct["C"])?);

  return Ok((s, c))
}

fn run_show(dal: &mut db::DAL) -> Result<(), Box<Error>> {
    env_logger::try_init()?;

    let tokens = dal.get_tokens()?;
    for t in tokens.iter() {
        let bytes_len = big::MODBYTES + big::MODBYTES + 1;
        let mut bytes = vec![0; bytes_len];
        t.1.tobytes(&mut bytes, false);
        let x = &bytes[1..big::MODBYTES + 1];
        let y = &bytes[big::MODBYTES + 1..big::MODBYTES + big::MODBYTES + 1];

        println!("***\ntoken: {}, p: (x={}, y={})\n***\n", hex::encode(&t.0), hex::encode(x), hex::encode(y));
    }

    Ok(())
}

#[allow(non_snake_case)]
fn run_client(dal: &mut db::DAL) -> Result<(), Box<Error>> {
  env_logger::try_init()?;

  let settings : ClientSettings = ClientSettings::new("client_settings.yaml")?;

  let mut rng = rand::thread_rng();
  let num_tokens = 5;
  let (request, tokens) = prepare_issue_request(num_tokens, &mut rng);

  let commitment_struct : HashMap<String, String> = serde_json::from_str(&fs::read_to_string(settings.commitment_path)?)?;

  let G = ecc::ecp_from_bytes(&base64::decode(&commitment_struct["G"])?)?;
  let Y = ecc::ecp_from_bytes(&base64::decode(&commitment_struct["H"])?)?;


  let buf = net::send_request(&settings.server_address, &request)?;
  let resp : Vec<String> = serde_json::from_slice(&base64::decode(&String::from_utf8(buf)?)?)?;
  println!("resp: {:?}", resp);

  let mut signed_blinded_tokens = vec![];
  for i in 0..num_tokens {
      let ecp = ecc::ecp_from_bytes(&base64::decode(&resp[i as usize])?)?;
      signed_blinded_tokens.push(ecp);
  }

  debug!("parsed points");

  let batch_proof_str = &base64::decode(&resp[resp.len() - 1 as usize])?["batch-proof=".len()..];
  debug!("batch_proof: {}", String::from_utf8(batch_proof_str.to_vec())?);
  let (s, c) = parse_batch_proof(batch_proof_str)?;
  debug!("s,c: {},{}", s, c);
  let unblinded_tokens = process_issue_response(&tokens, &signed_blinded_tokens, &G, &Y, &s, &c)?;
  for i in 0..num_tokens {
      dal.add_token(&tokens[i as usize].0, &unblinded_tokens[i as usize])?;
  }

  Ok(())
}

#[allow(non_snake_case)]
fn run_redeem(dal: &mut db::DAL, host: &str, path: &str) -> Result<(), Box<Error>> {
  env_logger::try_init()?;

  let settings : ClientSettings = ClientSettings::new("client_settings.yaml")?;

  let token = dal.pop_next_token()?;

  let redeem_request = prepare_redeem_request(&token.0, &token.1, host, path)?;
  debug!("redeem_request: {}", redeem_request.bl_sig_req);
  let buf = net::send_request(&settings.server_address, &redeem_request)?;
  debug!("got redeem response: {}", String::from_utf8(buf)?);

  Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 1 {
        print_usage();
        std::process::exit(1);
    }

    let mut dal = match db::DAL::new("tokens_client.db") {
        Ok(d) => d,
        Err(e) => {
            println!("error: {}\n", e);
            print_usage();
            std::process::exit(1);
        }
    };

    let run_result = match args[1].as_str() {
        "acquire" => run_client(&mut dal),
        "show" => run_show(&mut dal),
        "redeem" => {
            if args.len() < 4 {
                Err("not enough arguments.".into())
            } else {
                run_redeem(&mut dal, &args[2], &args[3])
            }
        },
        _ => Err(format!("unknown command: {}", args[1]).into())
    };
    match run_result {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            println!("error: {}\n", e);
            print_usage();
            std::process::exit(1);
        }
    }
}

fn print_usage() {
    let mut usage = String::new();
    usage += "commands:";
    usage += "\n\tacquire: request 5 tokens from the server.";
    usage += "\n\tshow:    show available tokens.";
    usage += "\n\tredeem:  redeem the next available token.";

    println!("{}", usage);
}
