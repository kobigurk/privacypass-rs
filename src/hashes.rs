use amcl::hash256::HASH256;
use super::types::curve::{big, ecp::ECP};

use std::error::Error;


// H_1
// more-or-less based on ECVRF_hash_to_curve1
pub fn hash_to_curve(data: &[u8]) -> Result<ECP, Box<Error>> {
    let mut ctr : [u8; 4] = [0; 4];
    let mut sh = HASH256::new();
    sh.process_array(&"1.2.840.10045.3.1.7 point generation seed".as_bytes());
    let mut data_to_hash = data.to_vec();
    for i in 0..10 {
        ctr[0] = i as u8;

        sh.process_array(&data_to_hash);
        sh.process_array(&ctr);

        let h = sh.hash();
        debug!("h: {:x?}", h);
        let byte_len = big::MODBYTES;
        let mut point_bytes = vec![0; byte_len+1];

        point_bytes[1..byte_len+1].copy_from_slice(&h[..byte_len]);

        point_bytes[0] = 0x02;
        let p = ECP::frombytes(&point_bytes);
        if !p.is_infinity() {
            return Ok(p);
        }

        point_bytes[0] = 0x03;
        let p = ECP::frombytes(&point_bytes);
        if !p.is_infinity() {
            return Ok(p);
        }
        sh.init();

        data_to_hash = h.to_vec();
    }

    return Err("infinity".into());
}

// H_3
pub fn hash_points(points: &[&ECP]) -> Vec<u8> {
    let mut sh = HASH256::new();
	let bytes_len = big::MODBYTES + big::MODBYTES + 1;
    for p in points.iter() {
        let mut bytes = vec![0; bytes_len];
        p.tobytes(&mut bytes, false);
        sh.process_array(&bytes);
    }

    sh.hash().to_vec()
}

// H_2
pub fn hash_for_redemption(t: &[u8], n: &ECP) -> Vec<u8> {
    let mut input = vec![];
    input.extend(t.to_vec().iter().cloned());
    let bytes_len = big::MODBYTES + big::MODBYTES + 1;
    let mut bytes = vec![0; bytes_len];
    n.tobytes(&mut bytes, false);
    input.append(&mut bytes);

    hmac(b"hash_derive_key", &input)
}

pub fn hash_for_request_binding(derived_key: &[u8], shared_info: &[u8]) -> Vec<u8> {
    let mut input = vec![];
    input.extend(shared_info.to_vec().iter().cloned());

    hmac(derived_key, &input)
}

pub fn hmac(key: &[u8], input: &[u8]) -> Vec<u8> {
    debug!("key: {:x?}, input: {:x?}", key, input);
    let block_size = 64;
    let mut processed_key = vec![0; block_size];
    if key.len() > block_size {
        let mut sh = HASH256::new();
        sh.process_array(key);
        let key_hash = sh.hash();
        processed_key.copy_from_slice(&key_hash);
    } else {
        processed_key[..key.len()].copy_from_slice(&key);
    }
    let key = &processed_key;
    debug!("processed key: {:x?}", key);

    let mut o_key_pad = vec![0; key.len()];
    o_key_pad.copy_from_slice(key);
    for k in o_key_pad.iter_mut() {
        *k = *k^0x5c;
    }
    debug!("o_key_pad: {:x?}", o_key_pad);

    let mut i_key_pad = vec![0; key.len()];
    i_key_pad.copy_from_slice(key);
    for k in i_key_pad.iter_mut() {
        *k = *k^0x36;
    }
    debug!("i_key_pad: {:x?}", i_key_pad);

    let mut inner = HASH256::new();
    inner.process_array(&i_key_pad);
    inner.process_array(input);
    let inner_hash = inner.hash();

    let mut outer = HASH256::new();
    outer.process_array(&o_key_pad);
    outer.process_array(&inner_hash);

    outer.hash().to_vec()
}

mod test {

    #[test]
    fn test_hash_to_curve() {
        let b : [u8; 10] = [0; 10];
        let h = hash_to_curve(&b);
        let mut p = h.unwrap();
        p.affine();

        let x = p.getx();
        let y = p.gety();

        let expected_x = BIG::from_hex("E7ECEBBC590BC88B3761FA6CD03D749F87463DABB67021A5C6768C25EC68B3F2".to_string());
        let expected_y = BIG::from_hex("F0F2017187832508873AE2C6F37519B1C5F4C9167B381B33C33600A560024892".to_string());

        let p2 = ECP::new_bigs(&expected_x, &expected_y);
        assert!(p == p2);
    }

    #[test]
    fn test_hmac() {
        env_logger::try_init();
        let h = hmac(b"key", b"The quick brown fox jumps over the lazy dog");
        debug!("hmac: {:x?}", h);
        assert!(h == &[0xf7, 0xbc, 0x83, 0xf4, 0x30, 0x53, 0x84, 0x24, 0xb1, 0x32, 0x98, 0xe6, 0xaa, 0x6f, 0xb1, 0x43, 0xef, 0x4d, 0x59, 0xa1, 0x49, 0x46, 0x17, 0x59, 0x97, 0x47, 0x9d, 0xbc, 0x2d,
 0x1a, 0x3c, 0xd8])
    }
}
