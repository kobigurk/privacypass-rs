use super::types::curve::big::BIG;
use amcl::arch::Chunk;

pub fn big_from_int(n: isize) -> BIG {
    let mut m = BIG::new();
    m.w[0] = n as Chunk;
    m
}

pub fn big_from_bytes(n: &[u8]) -> BIG {
    let mut m = BIG::new();
    for i in 0..(n.len() as usize) {
        m.fshl(8);
        m.w[0] += (n[i] & 0xff) as Chunk;
    }
    m
}

pub fn big_to_bytes(n: &BIG, i_len: usize) -> Vec<u8> {
    let mut bytes = vec![];
    let mut n_copy = BIG::new_copy(n);
    n_copy.norm();
    for _i in 0..i_len {
        bytes.push((n_copy.w[0] & 0xff) as u8);
        n_copy.fshr(8);
    }
    bytes.reverse();
    bytes
}

#[test]
fn test_big_from_int() {
    let b = big_from_int(5);
    let bs = i2osp(&b, 3);
    let expected_bs : &[u8] = &[5, 0, 0];
    assert!(expected_bs == bs.as_slice());
}
