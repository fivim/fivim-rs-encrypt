use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key,
};
use std::{convert::TryInto, error::Error};

use anyhow::Error as anyhowError;

fn ccm_error_to_anyhow(err: ccm::Error) -> anyhowError {
    anyhowError::msg(format!("CCM error: {}", err))
}

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;

pub fn encrypt(
    sss: &str,
    key_vec: [u8; KEY_LEN],
    nonce_vec: [u8; NONCE_LEN],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let key: Key<Aes256Gcm> = key_vec.into();
    let cipher = Aes256Gcm::new(&key);
    let mut nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message
    nonce.copy_from_slice(&nonce_vec);

    match cipher.encrypt(&nonce, sss.as_ref()) {
        Ok(sss) => return Ok(sss),
        Err(e) => {
            let err = ccm_error_to_anyhow(e);
            return Err(err.into());
        }
    };
}

pub fn decrypt(
    ciphertext: &Vec<u8>,
    key_vec: [u8; KEY_LEN],
    nonce_vec: [u8; NONCE_LEN],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let kv: &[u8] = &key_vec[..];
    let ka: &[u8; KEY_LEN] = kv.try_into().unwrap();
    let key: &Key<Aes256Gcm> = ka.into();

    let mut nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    nonce.copy_from_slice(&nonce_vec);

    let cipher = Aes256Gcm::new(&key);
    match cipher.decrypt(&nonce, ciphertext.as_ref()) {
        Ok(sss) => return Ok(sss),
        Err(e) => {
            let err = ccm_error_to_anyhow(e);
            return Err(err.into());
        }
    }
}

// https://stackoverflow.com/questions/62480743/how-to-change-str-into-array-in-rust
pub fn key_from_string(sss: &String) -> [u8; KEY_LEN] {
    let s = sss.as_str();
    let mut array = [0u8; KEY_LEN];

    if s.len() != array.len() {
        // handle this somehow
        println!("correct length, expect {}, actual {}", KEY_LEN, s.len())
    }

    s.bytes()
        .zip(array.iter_mut())
        .for_each(|(b, ptr)| *ptr = b);

    return array;
}

// https://stackoverflow.com/questions/62480743/how-to-change-str-into-array-in-rust
pub fn nonce_from_string(sss: &String) -> [u8; NONCE_LEN] {
    let s = sss.as_str();
    let mut array = [0u8; NONCE_LEN];

    if s.len() != array.len() {
        // handle this somehow
        println!("correct length, expect {}, actual {}", NONCE_LEN, s.len())
    }

    s.bytes()
        .zip(array.iter_mut())
        .for_each(|(b, ptr)| *ptr = b);

    return array;
}

pub fn key_from_vec(sss: &Vec<u8>) -> [u8; KEY_LEN] {
    let mut array = [0u8; KEY_LEN];
    for index in 0..sss.len() {
        if index < KEY_LEN {
            array[index] = sss[index]
        }
    }

    return array;
}

pub fn nonce_from_vec(sss: &Vec<u8>) -> [u8; NONCE_LEN] {
    let mut array = [0u8; NONCE_LEN];
    for index in 0..sss.len() {
        if index < NONCE_LEN {
            array[index] = sss[index]
        }
    }

    return array;
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use fivim_rs_utils::hash as xu_hash;

    use crate::aes_gcm::{decrypt, encrypt, key_from_string, key_from_vec, nonce_from_string};

    #[test]
    fn test_aes_gcm() {
        let key_string = String::from_str("mnbvcxz9asdfghjkpoiuyt987654rew3").unwrap();
        let nonce_string = String::from_str("GUtggOGkHQto").unwrap();
        let text = "asdfzxcvasdfzxcvasdfzxcvasdfzxcvasdfzxcvasdfzxcvasdfzxcv";

        let rrr = encrypt(
            text,
            key_from_string(&key_string),
            nonce_from_string(&nonce_string),
        )
        .unwrap();
        println!(">>>> enc res:: {:?}, length :: {}", rrr, rrr.len());

        let ddd = decrypt(
            &rrr,
            key_from_string(&key_string),
            nonce_from_string(&nonce_string),
        )
        .unwrap();
        println!(">>>> dec res:: {:?}", String::from_utf8(ddd).unwrap());
    }

    fn gen_nonce_from_key(pwd: &Vec<u8>) -> String {
        return xu_hash::sha256_by_bytes(pwd)[0..12].to_string();
    }

    #[test]
    fn test_aes_gcm2() {
        let text = "aaaaaaaaaaa,,,,,,,,,,,,,,,,kkkkkkkkkkkkkkkkk";
        let key_vec: Vec<u8> = [
            24, 0, 192, 14, 38, 62, 0, 193, 0, 245, 209, 0, 36, 12, 136, 136, 14, 166, 217, 128,
            192, 166, 25, 217, 24, 245, 245, 38, 128, 62, 209, 36,
        ]
        .to_vec();
        let nonce_string = gen_nonce_from_key(&key_vec);

        let eee = encrypt(
            text,
            key_from_vec(&key_vec),
            nonce_from_string(&nonce_string),
        )
        .unwrap();

        let ened = STANDARD.encode(eee);
        println!("encrypted base64: {}", ened);

        // let tttt =
        //     "LInPhOaAfco+LXgNliiSbhlMV7Iy6bwDFgQYcsEydrrzNIfiQ/AWp10aEG+LoADeD0ZHrgZGVg==".to_string();

        let bv = match STANDARD.decode(ened) {
            Ok(o) => o,
            Err(e) => {
                println!("decode base64 error: {}", e.to_string());
                return;
            }
        };

        let ddd = decrypt(
            &bv,
            key_from_vec(&key_vec),
            nonce_from_string(&nonce_string),
        )
        .unwrap();

        println!("decode result: {:?}", ddd);

        match String::from_utf8(ddd) {
            Ok(o) => {
                println!("decoded plaintext: {}", o);
            }
            Err(e) => {
                println!("convert vec to string error: {}", e.to_string());
                return;
            }
        };
    }
}
