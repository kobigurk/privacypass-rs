use super::{hashes, types, converters};

use super::types::curve::big::BIG;
use amcl::rand::RAND;

use rand::Rng;

use std::cmp::Ordering;

use sha3::Shake256;
use sha3::digest::{Input, ExtendableOutput ,XofReader};

pub fn rand_big(rng: &mut RAND) -> BIG {
    BIG::random(rng)
}

pub fn new_seeded_rand(seed: &[u8]) -> RAND {
    let mut rng = RAND::new();

    let seed_len = seed.len();

    rng.clean();
    rng.seed(seed_len,&seed);

    rng
}

pub fn new_rand<R: Rng>(rng: &mut R) -> RAND {
    let seed_len = 1024;
    let mut seed = vec![0; seed_len];
    for i in 0..seed_len {
        let r = rng.gen();
        seed[i] = r;
    }

    new_seeded_rand(&seed)
}

pub fn new_rand_vec<R: Rng>(size: usize, rng: &mut R) -> Vec<u8> {
    let mut bytes = vec![0; size];
    for i in 0..size {
        let r = rng.gen();
        bytes[i] = r;
    }

    bytes
}

pub fn init_prng(points: &[&types::curve::ecp::ECP]) -> impl XofReader {
    let mut hasher = Shake256::default();
    let z = hashes::hash_points(&points);
    hasher.input(&z);
    let prng = hasher.xof_result();

    prng
}

pub fn rand_scalar_from_rng<R: Rng>(rng: &mut R) -> types::curve::big::BIG {
    let seed = new_rand_vec(256, rng);

    let mut hasher = Shake256::default();
    hasher.input(&seed);
    let mut prng = hasher.xof_result();

    rand_scalar_from_prng(&mut prng)
}

pub fn rand_scalar_from_prng(prng: &mut XofReader) -> types::curve::big::BIG {
    let curve_order_big = types::curve::big::BIG::new_ints(&types::curve::rom::CURVE_ORDER);

    let zero = types::curve::big::BIG::new();
    let bytes_len = types::curve::big::MODBYTES;
    let mut bytes = vec![0; bytes_len];
    prng.read(&mut bytes);
    let mut c = converters::big_from_bytes(&bytes);
    c.norm();
    if c.cmp(&curve_order_big) != Ordering::Less {
        c.sub(&curve_order_big);
    }
    if c.cmp(&zero) != Ordering::Greater {
        c.add(&curve_order_big);
    }
    c.norm();

    c
}

#[test]
fn test_new_seeded_rand() {
    let seed : [u8; 24] = [1; 24];
    let mut r = new_seeded_rand(&seed);
    assert!(r.getbyte() == (173 as u8));
}

#[test]
fn test_new_rand() {
    let mut rng = rand::thread_rng();
    new_rand(&mut rng);
}

#[test]
fn test_new_rand_vec() {
    let mut rng = rand::thread_rng();
    let rand_vec_len = 1024;
    let bs = new_rand_vec(rand_vec_len, &mut rng);
    assert!(bs.len() == rand_vec_len);
}
