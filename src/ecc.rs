use super::types;

use std::error::Error;

pub fn ecp_from_bytes(bytes: &[u8]) -> Result<types::curve::ecp::ECP, Box<Error>> {
    let p = types::curve::ecp::ECP::frombytes(&bytes);
    if !p.is_infinity() {
        return Ok(p);
    }

    return Err("can't parse ecp".into());
}
