#![allow(non_snake_case)]

use super::{hashes, random, converters, ecc, types, client, mac, db};

use std::error::Error;
use rand::Rng;
use std::collections::HashMap;
use std::cmp::Ordering;

use config::{ConfigError, Config, File};

#[derive(Debug, Deserialize)]
pub struct ServerSettings {
    pub listen_address: String,
    pub secret_key_path: String,
    pub commitment_path: String,
    pub max_tokens: u8,
}

impl ServerSettings {
    pub fn new(config_path: &str) -> Result<Self, ConfigError> {
        let mut s = Config::new();
        s.merge(File::with_name(config_path))?;
        s.try_into()
    }
}

pub fn sign_blinded_token(
    x: &types::curve::big::BIG,
    blinded_token: &types::curve::ecp::ECP) -> types::curve::ecp::ECP {

    blinded_token.mul(x)
}

pub fn batch_dleq<R: Rng>(
    x: &types::curve::big::BIG,
    Zs: &[types::curve::ecp::ECP], Ms: &[types::curve::ecp::ECP],
    Y: &types::curve::ecp::ECP, G: &types::curve::ecp::ECP,
    rng: &mut R) -> (types::curve::big::BIG, types::curve::big::BIG) {

    let mut ps = vec![];
    ps.push(G);
    debug!("G: {}", G);
    ps.push(Y);
    debug!("Y: {}", Y);
    for i in 0..Ms.len() {
        ps.push(&Ms[i]);
        debug!("Ms[{}]: {}", i, Ms[i]);
        ps.push(&Zs[i]);
        debug!("Zs[{}]: {}", i, Zs[i]);
    }

    let mut prng = random::init_prng(&ps);

    let mut M = types::curve::ecp::ECP::new();
    let mut Z = types::curve::ecp::ECP::new();
    for i in 0..Zs.len() {
        let c = random::rand_scalar_from_prng(&mut prng);
        debug!("c[{}]: {}", i, c);
        M.add(&Ms[i].mul(&c));
        Z.add(&Zs[i].mul(&c));
    }

    dleq(x, &Z, &M, Y, G, rng)
}


pub fn dleq<R: Rng>(
    x: &types::curve::big::BIG,
    Z: &types::curve::ecp::ECP, M: &types::curve::ecp::ECP,
    Y: &types::curve::ecp::ECP, G: &types::curve::ecp::ECP,
    rng: &mut R) -> (types::curve::big::BIG, types::curve::big::BIG) {

    let zero = types::curve::big::BIG::new();

    let curve_order_big = types::curve::big::BIG::new_ints(&types::curve::rom::CURVE_ORDER);

    //let mut k = random::rand_big(&mut big_rng);
    let k = random::rand_scalar_from_rng(rng);
    debug!("k: {}", k);
    let A = G.mul(&k);
    debug!("A: {}", A);
    let B = M.mul(&k);
    debug!("B: {}", B);

    let c_hash = hashes::hash_points(&[G, Y, M, Z, &A, &B]);
    let c = converters::big_from_bytes(&c_hash);
    debug!("c: {}", c);
    debug!("curve_order: {}", curve_order_big);
    let cx = types::curve::big::BIG::modmul(&c, x, &curve_order_big);
    debug!("x: {}", x);
    debug!("cx: {}", cx);

    let mut s = types::curve::big::BIG::new_copy(&k);
    s.sub(&cx);
    debug!("s: {}", s);
    if s.cmp(&zero) == Ordering::Less {
        s.add(&curve_order_big);
        s.norm();
    }

    debug!("calling verify_dleq_proof");
    let verify_result = !client::verify_dleq_proof(&c, &s, Z, M, Y, G).is_err();
    debug!("verify: {}", verify_result);

    (c, s)
}

pub fn check_mac(x: &types::curve::big::BIG, t: &[u8], request_binding: &[u8], observed_info: &[u8]) -> Result<(), Box<Error>> {
    let T = hashes::hash_to_curve(&t).unwrap();
    let N = T.mul(x);
    let sk = hashes::hash_for_redemption(t, &N);
    let request_binding_calc = hashes::hash_for_request_binding(&sk, observed_info);
    if request_binding == request_binding_calc.as_slice() {
        return Ok(());
    } else {
        return Err(format!("request_binding and request_binding_calc are different: {:x?} != {:x?}", request_binding, request_binding_calc).into());
    }
}

pub struct ServerProcessor<'a> {
    pub secret_key: types::curve::big::BIG,
    pub G: types::curve::ecp::ECP,
    pub Y: types::curve::ecp::ECP,
    pub dal: &'a mut db::DAL,
}

impl<'a> ServerProcessor<'a> {
    pub fn new(secret_key_bytes: &[u8], g_bytes: &[u8], dal: &'a mut db::DAL) -> Result<Self, Box<Error>> {
        let x = converters::big_from_bytes(secret_key_bytes);
        let g = ecc::ecp_from_bytes(g_bytes)?;
        let processor = ServerProcessor {
            secret_key: x,
            G: g,
            Y: g.mul(&x),
            dal: dal,
        };

        Ok(processor)
    }

    pub fn process_server_message<R: Rng>(&mut self, buf: &[u8], rng: &mut R) -> Result<String, Box<Error>> {
        let request_wrapper : types::ClientRequestWrapper = serde_json::from_slice(&buf)?;
        println!("bl_sig_req: {:?}", request_wrapper.bl_sig_req);
        let request : types::ClientRequest = serde_json::from_slice(&base64::decode(&request_wrapper.bl_sig_req)?)?;
        println!("request type: {}", request.type_f);

        match request.type_f.as_ref() {
            "Issue" => self.process_issue(&request, rng),
            "Redeem" => self.process_redeem(&request, &request_wrapper.host, &request_wrapper.http),
            x => return Err(format!("unknown request: {}", x).into())
        }
    }

    fn process_issue<R: Rng>(&self, request: &types::ClientRequest, rng: &mut R) -> Result<String, Box<Error>> {
        let mut Ms = vec![];
        let mut Zs = vec![];
        for m_str in request.contents.iter() {
            let M = types::curve::ecp::ECP::frombytes(&base64::decode(m_str)?);
            Ms.push(M);
            Zs.push(M.mul(&self.secret_key));
        }

        let (c, s) = batch_dleq(&self.secret_key, &Zs, &Ms, &self.Y, &self.G, rng);
        println!("c, s: {:?}, {:?}", c, s);

        let mut proof_struct : HashMap<String, String> = HashMap::new();
        proof_struct.insert("R".to_string(), base64::encode(&converters::big_to_bytes(&s, 32)));
        proof_struct.insert("C".to_string(), base64::encode(&converters::big_to_bytes(&c, 32)));

        let mut batch_proof_struct : HashMap<String, String> = HashMap::new();
        batch_proof_struct.insert("P".to_string(), base64::encode(&serde_json::to_vec(&proof_struct)?));

        let batch_proof_elem = base64::encode(&format!("batch-proof={}", serde_json::to_string(&batch_proof_struct)?).as_bytes());

        let mut resp_arr = vec![];
        for z in Zs {
            let bytes_len = types::curve::big::MODBYTES + 1;
            let mut bytes = vec![0; bytes_len];
            z.tobytes(&mut bytes, true);
            resp_arr.push(base64::encode(&bytes));
        }
        resp_arr.push(batch_proof_elem);
        let response_str = base64::encode(serde_json::to_string(&resp_arr)?.as_bytes());

        Ok(response_str)

    }

    fn process_redeem(&mut self, request: &types::ClientRequest, host: &str, path: &str) -> Result<String, Box<Error>> {
        let token = base64::decode(&request.contents[0])?;
        let request_binding = base64::decode(&request.contents[1])?;

        let shared_info = mac::build_shared_info(host, path);
        check_mac(&self.secret_key, &token, &request_binding, &shared_info)?;

        self.dal.store_spent(&token)?;

        Ok("success".into())
    }
}

mod test {
    /*
    pub fn generator() -> types::curve::ecp::ECP {
        let gx_bytes : &[u8] = &[44, 132, 52, 73, 132, 117, 108, 247, 90, 43, 242, 238, 44, 23, 21, 194, 217, 211, 19, 150, 236, 240, 158, 216, 27, 104, 48, 62, 172, 96, 26, 148];
        let gy_bytes : &[u8] = &[43, 227, 193, 101, 167, 121, 122, 231, 53, 180, 255, 94, 145, 199, 82, 15, 28, 74, 222, 40, 224, 30, 196, 53, 62, 164, 34, 155, 133, 106, 12, 106];
        let gx = converters::big_from_bytes(gx_bytes);
        let gy = converters::big_from_bytes(gy_bytes);

        let g = types::curve::ecp::ECP::new_bigs(&gx, &gy);

        g
    }
    */



    #[test]
    fn test_sign_blinded_token() {
        let seed = [1,2,3,4, 5,6,7,8, 9,10,11,12, 13,14,15,16];
        let mut rng = SmallRng::from_seed(seed);

        let (t, r, M) = client::generate_and_blind_token(&mut rng);

        let mut big_rng = random::new_rand(&mut rng);
        let x = random::rand_big(&mut big_rng);

        let Z = sign_blinded_token(&x, &M);
        let Z_x = Z.getx();
        let Z_y = Z.gety();
        debug!("x,y: {},{}", Z_x, Z_y);
        let expected_Z_x = types::curve::big::BIG::fromstring("D15A7BBD590EFF82E7DA0B1EC20385F793A9908F7A54A2A10247DB7A5755F1EC".to_string());
        let expected_Z_y = types::curve::big::BIG::fromstring("D3B420D5AEFCEFF02E0E9A06E8860D938E9F97A39976ADC17A2B8BB0E61E1F26".to_string());
        assert!(Z_x == expected_Z_x);
        assert!(Z_y == expected_Z_y);
    }

    #[test]
    fn test_server() {
        let seed = [1,2,3,4, 5,6,7,8, 9,10,11,12, 13,14,15,16];
        let mut rng = SmallRng::from_seed(seed);

        let (t, r, M) = client::generate_and_blind_token(&mut rng);

        let mut big_rng = random::new_rand(&mut rng);
        //let x = random::rand_big(&mut big_rng);
        let x_bytes : &[u8] = &[33, 110, 57, 18, 212, 211, 59, 37, 40, 180, 8, 222, 219, 231, 42, 155, 63, 1, 40, 188, 196, 228, 120, 55, 18, 158, 176, 128, 123, 138, 106, 178];
        let x = converters::big_from_bytes(x_bytes);
        let Z = sign_blinded_token(&x, &M);
        let G = generator();
        let Y = G.mul(&x);

        debug!("Y: {}", Y);
        debug!("Y_x, Y_y: {}, {}", Y.getx(), Y.gety());

        let (c, s) = dleq(
            &x,
            &Z, &M,
            &Y, &G,
            &mut rng
        );

        client::verify_dleq_proof(&c, &s, &Z, &M, &Y, &G).unwrap();

        let N = client::unblind_signature(&Z, &r);
        let shared_info: [u8; 5] = [0; 5];
        let request_binding = client::mac(&shared_info, &t, &N);

        check_mac(&x, &t, &request_binding, &shared_info).unwrap();
    }
}
