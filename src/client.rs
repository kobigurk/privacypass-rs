#![allow(non_snake_case)]

use super::{hashes, random, converters, types, mac};
use rand::Rng;
use std::error::Error;

use config::{ConfigError, Config, File};

#[derive(Debug, Deserialize)]
pub struct ClientSettings {
    pub server_address: String,
    pub commitment_path: String,
    pub num_tokens: u8,
}

impl ClientSettings {
    pub fn new(config_path: &str) -> Result<Self, ConfigError> {
        let mut s = Config::new();
        s.merge(File::with_name(config_path))?;
        s.try_into()
    }
}


#[allow(non_snake_case)]
pub fn generate_and_blind_token<R: Rng>(rng: &mut R) -> (Vec<u8>, types::curve::big::BIG, types::curve::ecp::ECP) {
    let t = random::new_rand_vec(1024, rng);
    debug!("t: {:x?}", t);

    let T = hashes::hash_to_curve(&t).unwrap();
    debug!("T: {}", T);

    //let r = random::rand_big(&mut big_rng);
    let r = random::rand_scalar_from_rng(rng);
    debug!("r: {}", r);

    let M = T.mul(&r);
    debug!("M: {}", M);

    (t, r, M)
}

pub fn unblind_signature(Z : &types::curve::ecp::ECP, r: &types::curve::big::BIG) -> types::curve::ecp::ECP {
    let r_inv = {
        let order = types::curve::big::BIG::new_ints(&types::curve::rom::CURVE_ORDER);
        let mut r_copy = types::curve::big::BIG::new_copy(r);
        r_copy.invmodp(&order);
        r_copy
    };

    let N = Z.mul(&r_inv);
    N
}

pub fn verify_dleq_proof(
    c: &types::curve::big::BIG, s: &types::curve::big::BIG,
    Z: &types::curve::ecp::ECP, M: &types::curve::ecp::ECP,
    Y: &types::curve::ecp::ECP, G: &types::curve::ecp::ECP) -> Result<(), Box<Error>> {

    debug!("start verify_dleq_proof");
    debug!("c,s: {}, {}", c, s);
    let mut A_calc = G.mul(s);
    debug!("A_calc 1: {}", A_calc);
    A_calc.add(&Y.mul(c));
    debug!("A_calc 2: {}", A_calc);
    A_calc.affine();
    debug!("A_calc 3: {}", A_calc);

    let mut B_calc = M.mul(s);
    B_calc.add(&Z.mul(c));
    B_calc.affine();
    debug!("B_calc: {}", B_calc);

    let c_calc = hashes::hash_points(&[G, Y, M, Z, &A_calc, &B_calc]);
    let c_calc = converters::big_from_bytes(&c_calc);
    debug!("c_calc: {}", c_calc);
    if *c == c_calc {
        return Ok(());
    } else {
        return Err(format!("c and c' are different: {} != {}", c, c_calc).into());
    }
}

pub fn mac(
    shared_info: &[u8],
    t: &[u8],
    N: &types::curve::ecp::ECP) -> Vec<u8> {

    let T = hashes::hash_to_curve(t).unwrap();
    debug!("Tx, Ty: {:x?}, {:x?}", T.getx(), T.gety());
    let sk = hashes::hash_for_redemption(t, N);
    debug!("sk: {:x?}", sk);
    let request_binding = hashes::hash_for_request_binding(&sk, shared_info);
    debug!("request_binding: {:x?}", request_binding);

    request_binding
}

pub fn prepare_issue_request<R: Rng>(num_tokens: u8, rng: &mut R) -> (types::ClientRequestWrapper,
                                                                      Vec<(Vec<u8>, types::curve::big::BIG, types::curve::ecp::ECP)>) {
    let mut tokens = vec![];
    let mut contents = vec![];
    let bytes_len = types::curve::big::MODBYTES + 1;
    for _i in 0..num_tokens {
        let (t, r, M) = generate_and_blind_token(rng);
        let mut bytes = vec![0; bytes_len];
        M.tobytes(&mut bytes, true);
        contents.push(base64::encode(&bytes));
        tokens.push((t, r, M));
    }

    let req = types::ClientRequest {
        type_f: "Issue".to_string(),
        contents: contents,
    };

    let wrapped_req = types::ClientRequestWrapper {
        bl_sig_req: base64::encode(&serde_json::to_string(&req).unwrap()),
        host: "".to_string(),
        http: "".to_string(),
    };

    (wrapped_req, tokens)
}

pub fn process_issue_response(
    tokens: &[(Vec<u8>, types::curve::big::BIG, types::curve::ecp::ECP)], // (t, r, M)
    signed_blinded_tokens: &[types::curve::ecp::ECP],
    G: &types::curve::ecp::ECP, Y: &types::curve::ecp::ECP,
    s: &types::curve::big::BIG, c: &types::curve::big::BIG) -> Result<Vec<types::curve::ecp::ECP>, Box<Error>> {

    let mut ps = vec![];
    ps.push(G);
    debug!("G: {}", G);
    ps.push(Y);
    debug!("Y: {}", Y);

    for i in 0..tokens.len() {
        ps.push(&tokens[i].2);
        debug!("Ms[{}]: {}", i, tokens[i].2);
        ps.push(&signed_blinded_tokens[i]);
        debug!("Zs[{}]: {}", i, signed_blinded_tokens[i]);
    }

    let mut prng = random::init_prng(&ps);

    let mut M = types::curve::ecp::ECP::new();
    let mut Z = types::curve::ecp::ECP::new();

    for i in 0..tokens.len() {
        let c = random::rand_scalar_from_prng(&mut prng);
        debug!("c[{}]: {}", i, c);
        M.add(&tokens[i].2.mul(&c));
        Z.add(&signed_blinded_tokens[i].mul(&c));
    }

    verify_dleq_proof(&c, &s, &Z, &M, &Y, &G)?;

    let mut unblinded_tokens = vec![];
    for i in 0..signed_blinded_tokens.len() {
        unblinded_tokens.push(unblind_signature(&signed_blinded_tokens[i], &tokens[i].1));
    }

    Ok(unblinded_tokens)
}

pub fn prepare_redeem_request(token: &[u8], N: &types::curve::ecp::ECP, host: &str, path: &str) -> Result<types::ClientRequestWrapper, Box<Error>> {

    let mut contents = vec![];
    contents.push(base64::encode(token));

    let shared_info = mac::build_shared_info(host, path);
    let request_binding = mac(&shared_info, token, N);
    contents.push(base64::encode(&request_binding));

    let req = types::ClientRequest {
        type_f: "Redeem".to_string(),
        contents: contents,
    };

    let wrapped_req = types::ClientRequestWrapper {
        bl_sig_req: base64::encode(&serde_json::to_string(&req)?),
        host: host.to_string(),
        http: path.to_string(),
    };

    Ok(wrapped_req)
}


mod test {

    #[test]
    fn test_client() {
        env_logger::try_init();
        let mut rng = rand::thread_rng();

        let (t, r, M) = generate_and_blind_token(&mut rng);
        let mut big_rng = random::new_rand(&mut rng);
        let x = random::rand_big(&mut big_rng);
        let Z = M.mul(&x);
        let N = unblind_signature(&Z, &r);

        let T = hashes::hash_to_curve(&t).unwrap();
        let expected_N = T.mul(&x);
        assert!(expected_N == N);
    }

    #[test]
    fn test_mac() {
        env_logger::try_init();
        let mut rng = rand::thread_rng();

        let (t, r, M) = generate_and_blind_token(&mut rng);
        let mut big_rng = random::new_rand(&mut rng);
        let x = random::rand_big(&mut big_rng);
        let Z = M.mul(&x);
        let N = unblind_signature(&Z, &r);

        mac(&[1,2,3], &t, &N);
    }
}
