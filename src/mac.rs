pub fn build_shared_info(host: &str, path: &str) -> Vec<u8> {
    let mut shared_info = vec![];
    shared_info.extend_from_slice(&"hash_request_binding".as_bytes());
    shared_info.extend_from_slice(&host.as_bytes());
    shared_info.extend_from_slice(&path.as_bytes());

    shared_info
}
