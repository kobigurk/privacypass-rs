use super::{types, ecc};

use std::io::Cursor;

use std::error::Error;

use rocksdb::DB;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

pub struct DAL {
    pub db: DB,
}

const CURRENT_TOKEN_KEY: &str = "current_token";
const FREE_TOKEN_KEY: &str = "free_token";
const TOKEN_KEY_PREFIX: &str = "token_";

impl DAL {
    pub fn new(db_path: &str) -> Result<DAL, Box<Error>> {
        let dal = DAL {
            db: DB::open_default(db_path)?,
        };
        Ok(dal)
    }

    pub fn add_token(&mut self, token: &[u8], signed_token: &types::curve::ecp::ECP) -> Result<(), Box<Error>> {
        let next_token_num = self.get_next_free_token()?;
        let next_token_num = next_token_num + 1;

        let point_bytes_len = types::curve::big::MODBYTES + 1;
        let mut point_bytes = vec![0; point_bytes_len];
        signed_token.tobytes(&mut point_bytes, true);

        let mut val = vec![];
        val.write_u32::<LittleEndian>(token.len() as u32)?;
        val.extend_from_slice(token);
        val.extend_from_slice(&point_bytes);

        let next_token_key = format!("{}{}", TOKEN_KEY_PREFIX, next_token_num);
        self.db.put(next_token_key.as_bytes(), &val)?;

        self.inc_next_free_token()?;

        Ok(())
    }

    pub fn get_tokens(&self) -> Result<Vec<(Vec<u8>,types::curve::ecp::ECP)>, Box<Error>> {
        let current_token_num = self.get_current_token()?;
        let next_token_num = self.get_next_free_token()?;
        if current_token_num == next_token_num {
            return Err("not enough tokens.".into());
        }

        let mut tokens = vec![];

        debug!("current_token_num: {}, next_token_num: {}", current_token_num, next_token_num);
        for i in current_token_num..next_token_num {
            let current_token_key = format!("{}{}", TOKEN_KEY_PREFIX, i);
            let stored_token_bytes : &[u8] = &*self.db.get(current_token_key.as_bytes())?.unwrap();

            let mut pos : usize = 0;

            let token_length_bytes = &stored_token_bytes[..4];
            let mut rdr = Cursor::new(token_length_bytes);
            let token_length = rdr.read_u32::<LittleEndian>()?;
            pos += 4;

            let token = &stored_token_bytes[pos..pos+(token_length as usize)];
            pos += token_length as usize;

            let ecp_length = types::curve::big::MODBYTES + 1;
            let p = ecc::ecp_from_bytes(&stored_token_bytes[pos..pos+(ecp_length as usize)])?;

            tokens.push((token.to_vec(), p));
        }

        Ok(tokens)
    }

    pub fn pop_next_token(&mut self) -> Result<(Vec<u8>,types::curve::ecp::ECP), Box<Error>> {
        let current_token_num = self.get_current_token()?;
        let next_token_num = self.get_next_free_token()?;
        if current_token_num == next_token_num {
            return Err("not enough tokens.".into());
        }

        let current_token_key = format!("{}{}", TOKEN_KEY_PREFIX, current_token_num);
        let stored_token_bytes : &[u8] = &*self.db.get(current_token_key.as_bytes())?.unwrap();

        let mut pos : usize = 0;

        let token_length_bytes = &stored_token_bytes[..4];
        let mut rdr = Cursor::new(token_length_bytes);
        let token_length = rdr.read_u32::<LittleEndian>()?;
        pos += 4;

        let token = &stored_token_bytes[pos..pos+(token_length as usize)];
        pos += token_length as usize;

        let ecp_length = types::curve::big::MODBYTES + 1;
        let p = ecc::ecp_from_bytes(&stored_token_bytes[pos..pos+(ecp_length as usize)])?;

        self.inc_current_token()?;

        Ok((token.to_vec(), p))
    }

    fn get_current_token(&self) -> Result<i64, Box<Error>> {
        let current_token_num_db = self.db.get(CURRENT_TOKEN_KEY.as_bytes())?;
        let current_token_num_db : Result<_, Box<Error>> = match current_token_num_db {
            Some(s) => Ok(s),
            None => Err("current token num is undefined.".into()),
        };
        if current_token_num_db.is_err() {
            return Ok(0);
        };

        let current_token_num_db = current_token_num_db.unwrap();
        let mut rdr = Cursor::new(&*current_token_num_db);
        let current_token = rdr.read_u32::<LittleEndian>()?;
        Ok(current_token as i64)
    }

    fn get_next_free_token(&self) -> Result<i64, Box<Error>> {
        let next_token_num_db = self.db.get(FREE_TOKEN_KEY.as_bytes())?;
        let next_token_num_db : Result<_, Box<Error>> = match next_token_num_db {
            Some(s) => Ok(s),
            None => Err("next token num is undefined.".into()),
        };
        if next_token_num_db.is_err() {
            return Ok(-1);
        };

        let next_token_num_db = next_token_num_db.unwrap();
        let mut rdr = Cursor::new(&*next_token_num_db);
        let next_token = rdr.read_u32::<LittleEndian>()?;
        Ok(next_token as i64)
    }

    fn inc_current_token(&mut self) -> Result<i64, Box<Error>> {
        let current_token = self.get_current_token()?;
        let current_token_num = current_token + 1;
        let mut current_token_inc = vec![];
        current_token_inc.write_u32::<LittleEndian>(current_token_num as u32)?;
        self.db.put(CURRENT_TOKEN_KEY.as_bytes(), &current_token_inc)?;
        Ok(current_token_num as i64)
    }

    fn inc_next_free_token(&mut self) -> Result<u32, Box<Error>> {
        let next_token = self.get_next_free_token()?;
        let next_token_num = next_token + 1;
        let mut next_token_inc = vec![];
        next_token_inc.write_u32::<LittleEndian>(next_token_num as u32)?;
        self.db.put(FREE_TOKEN_KEY.as_bytes(), &next_token_inc)?;
        Ok(next_token_num as u32)
    }

    pub fn store_spent(&mut self, token: &[u8]) -> Result<(), Box<Error>> {
        let stored_token_bytes_db = self.db.get(token)?;
        if !stored_token_bytes_db.is_none() {
            return Err("token already spent.".into());
        }

        self.db.put(token, &[1])?;
        Ok(())
    }
}
