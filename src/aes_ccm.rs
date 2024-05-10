use aes::Aes256;
use base64::{engine::general_purpose::STANDARD, Engine};
use ccm::{
    aead::{generic_array::typenum::Unsigned, Aead},
    consts::{U11, U12, U13, U8},
    Ccm, KeyInit,
};
use serde::Deserialize;
use std::convert::TryInto;
use std::str;

// Refer: https://users.rust-lang.org/t/is-there-any-pure-rust-code-to-decrypt-an-aes-ccm-data/90138/2
// Note: Key is not the password.
pub fn decrypt_direct(input: &str, key: &str) -> Vec<u8> {
    #[derive(Deserialize)]
    struct Input {
        iv: String,
        ct: String,
    }

    let input: Input = serde_json::from_str(input).unwrap();
    let iv = STANDARD.decode(input.iv).unwrap();
    let ct = STANDARD.decode(input.ct).unwrap();
    let key: Vec<u8> = key
        .split(" ")
        .flat_map(|chunk| u32::from_str_radix(chunk, 16).unwrap().to_be_bytes())
        .collect();

    fn decrypt_with<Alg: KeyInit + Aead>(key: &[u8], iv: &[u8], ct: &[u8]) -> Vec<u8> {
        Alg::new_from_slice(key)
            .unwrap()
            .decrypt(iv[..Alg::NonceSize::USIZE].try_into().unwrap(), &ct[..])
            .unwrap()
    }

    // SJCL automatically adjusts the nonce size, we must do so manually
    if ct.len() < 0x1_0008 {
        decrypt_with::<Ccm<Aes256, U8, U13>>(&key, &iv, &ct)
    } else if ct.len() < 0x100_0008 {
        decrypt_with::<Ccm<Aes256, U8, U12>>(&key, &iv, &ct)
    } else {
        decrypt_with::<Ccm<Aes256, U8, U11>>(&key, &iv, &ct)
    }
}
