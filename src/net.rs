use std::net::{Shutdown, TcpStream};
use std::error::Error;
use serde::Serialize;
use std::io::{Read, Write};

pub fn send_request<T: Serialize>(address: &str, request: &T) -> Result<Vec<u8>, Box<Error>> {
  let mut stream = TcpStream::connect(address)?;
  println!("Connected to the server!");

  let request_str = serde_json::to_string(&request)?;
  let msg = &request_str.into_bytes();
  stream.write(&msg)?;
  stream.flush()?;

  let mut buf = vec![0; 10*1024];
  let n = stream.read(&mut buf)?;
  stream.shutdown(Shutdown::Both)?;
  let buf = &buf[..n];
  println!("buf: {:?}", buf);
  Ok(buf.to_vec())
}
