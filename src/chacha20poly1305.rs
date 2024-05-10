// https://kerkour.com/rust-file-encryption

use anyhow::anyhow;
use chacha20poly1305::aead::stream;
use chacha20poly1305::{aead, XChaCha20Poly1305};
use std::fs::{self, File};
use std::io::{Read, Write};

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

const KEY_LEN: usize = 32;
const NONCE_LEN_SMALL: usize = 24;
const NONCE_LEN_LARGE: usize = 19;

pub const BUFFER_LEN_ENCRYPT: usize = 500;

pub fn encrypt_small_file(
    filepath: &str,
    dist: &str,
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN_SMALL],
) -> Result<(), anyhow::Error> {
    let cipher = XChaCha20Poly1305::new(key.into());

    let file_data = fs::read(filepath)?;

    let encrypted_file = cipher
        .encrypt(nonce.into(), file_data.as_ref())
        .map_err(|err| anyhow!("Encrypting small file: {}", err))?;

    fs::write(&dist, encrypted_file)?;

    Ok(())
}

pub fn decrypt_small_file(
    encrypted_file_path: &str,
    dist: &str,
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN_SMALL],
) -> Result<(), anyhow::Error> {
    let cipher = XChaCha20Poly1305::new(key.into());

    let file_data = fs::read(encrypted_file_path)?;

    let decrypted_file = cipher
        .decrypt(nonce.into(), file_data.as_ref())
        .map_err(|err| anyhow!("Decrypting small file: {}", err))?;

    fs::write(&dist, decrypted_file)?;

    Ok(())
}

pub fn decrypt_small_file_base64(
    encrypted_file_path: &str,
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN_SMALL],
) -> Result<String, anyhow::Error> {
    let cipher = XChaCha20Poly1305::new(key.into());

    let file_data = fs::read(encrypted_file_path)?;

    let decrypted_file = cipher
        .decrypt(nonce.into(), file_data.as_ref())
        .map_err(|err| anyhow!("Decrypting small file: {}", err))?;

    let ened = STANDARD.encode(decrypted_file);

    Ok(ened)
}

pub fn encrypt_large_file(
    source_file_path: &str,
    dist_file_path: &str,
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN_LARGE],
) -> Result<(), anyhow::Error> {
    let aead = XChaCha20Poly1305::new(key.as_ref().into());
    let mut stream_encryptor = stream::EncryptorBE32::from_aead(aead, nonce.as_ref().into());

    const BUFFER_LEN: usize = BUFFER_LEN_ENCRYPT;
    let mut buffer = [0u8; BUFFER_LEN];

    let mut source_file = File::open(source_file_path)?;
    let mut dist_file = File::create(dist_file_path)?;

    loop {
        let read_count = source_file.read(&mut buffer)?;

        if read_count == BUFFER_LEN {
            let ciphertext = stream_encryptor
                .encrypt_next(buffer.as_slice())
                .map_err(|err| anyhow!("Encrypting large file: {}", err))?;
            dist_file.write(&ciphertext)?;
        } else {
            let ciphertext = stream_encryptor
                .encrypt_last(&buffer[..read_count])
                .map_err(|err| anyhow!("Encrypting large file: {}", err))?;
            dist_file.write(&ciphertext)?;
            break;
        }
    }

    Ok(())
}

pub fn encrypt_large_file_content_base64(
    content: &Vec<u8>,
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN_LARGE],
) -> Result<String, anyhow::Error> {
    let mut step_start: usize = 0;
    let mut step_end = step_start + BUFFER_LEN_ENCRYPT;
    let mut res_buffer: Vec<u8> = [].to_vec();
    let bytes_size = content.len();

    let mut data_length: usize = 0;

    let aead = XChaCha20Poly1305::new(key.as_ref().into());
    let mut stream_encryptor = stream::EncryptorBE32::from_aead(aead, nonce.as_ref().into());

    loop {
        if step_end < bytes_size {
            let mut buffer = [0u8; BUFFER_LEN_ENCRYPT];
            buffer[..].clone_from_slice(&content[step_start..step_end]);
            let cipher_vec = stream_encryptor
                .encrypt_next(buffer.as_slice())
                .map_err(|err| {
                    anyhow!(
                        "Encrypt bytes step, error: {}, buffer len:{}, buffer: {:?}",
                        err,
                        buffer.len(),
                        buffer
                    )
                })?;
            data_length += &cipher_vec.len();
            res_buffer = [res_buffer, cipher_vec].concat();

            step_start += BUFFER_LEN_ENCRYPT;
            step_end += BUFFER_LEN_ENCRYPT;
        } else {
            // The last buffer
            let buffer_last = &content[step_start..bytes_size];
            let cipher_vec = stream_encryptor
                .encrypt_last(&buffer_last[..buffer_last.len()])
                .map_err(|err| anyhow!("Encrypting large file base64: {}", err))?;

            data_length += &cipher_vec.len();
            res_buffer = [res_buffer, cipher_vec].concat();

            break;
        }
    }

    let ened = STANDARD.encode(res_buffer);

    Ok(ened)
}

pub fn decrypt_large_file(
    encrypted_file_path: &str,
    dist: &str,
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN_LARGE],
) -> Result<(), anyhow::Error> {
    let aead = XChaCha20Poly1305::new(key.as_ref().into());
    let mut stream_decryptor = stream::DecryptorBE32::from_aead(aead, nonce.as_ref().into());

    const BUFFER_LEN: usize = BUFFER_LEN_ENCRYPT + 16;
    let mut buffer = [0u8; BUFFER_LEN];

    let mut encrypted_file = File::open(encrypted_file_path)?;
    let mut decrypted_file = File::create(dist)?;

    loop {
        let read_count = encrypted_file.read(&mut buffer)?;

        if read_count == BUFFER_LEN {
            let plaintext = stream_decryptor
                .decrypt_next(buffer.as_slice())
                .map_err(|err| anyhow!("Decrypting large file: {}", err))?;
            decrypted_file.write(&plaintext)?;
        } else if read_count == 0 {
            break;
        } else {
            let plaintext = stream_decryptor
                .decrypt_last(&buffer[..read_count])
                .map_err(|err| anyhow!("Decrypting large file: {}", err))?;
            decrypted_file.write(&plaintext)?;
            break;
        }
    }

    Ok(())
}

pub fn decrypt_large_file_base64(
    encrypted_file_path: &str,
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN_LARGE],
) -> Result<String, anyhow::Error> {
    let aead = XChaCha20Poly1305::new(key.as_ref().into());
    let mut stream_decryptor = stream::DecryptorBE32::from_aead(aead, nonce.as_ref().into());

    const BUFFER_LEN: usize = BUFFER_LEN_ENCRYPT + 16;
    let mut buffer = [0u8; BUFFER_LEN];

    let mut encrypted_file = File::open(encrypted_file_path)?;
    let mut decrypted_file: Vec<u8> = [].to_vec();

    loop {
        let read_count = encrypted_file.read(&mut buffer)?;

        if read_count == BUFFER_LEN {
            let plaintext = stream_decryptor
                .decrypt_next(buffer.as_slice())
                .map_err(|err| anyhow!("Decrypting large file: {}", err))?;
            decrypted_file.extend(&plaintext);
        } else if read_count == 0 {
            break;
        } else {
            let plaintext = stream_decryptor
                .decrypt_last(&buffer[..read_count])
                .map_err(|err| anyhow!("Decrypting large file: {}", err))?;
            decrypted_file.extend(&plaintext);
            break;
        }
    }

    let ened = STANDARD.encode(decrypted_file);

    Ok(ened)
}

pub fn encrypt_vec(input: &[u8], key_in: &[u8], nonce_in: &[u8]) -> Result<Vec<u8>, aead::Error> {
    let key = Key::from_slice(key_in);
    let nonce = Nonce::from_slice(nonce_in);
    let cipher = ChaCha20Poly1305::new(key);
    let ciphertext = cipher.encrypt(&nonce, input)?;
    let mut output = nonce.to_vec();
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

pub fn decrypt_vec(input: &[u8], key_in: &[u8], nonce_in: &[u8]) -> Result<Vec<u8>, aead::Error> {
    let key = Key::from_slice(key_in);
    let nonce = Nonce::from_slice(nonce_in);
    let cipher = ChaCha20Poly1305::new(key);
    let ciphertext = cipher.decrypt(&nonce, input)?;
    let mut output = nonce.to_vec();
    output.extend_from_slice(&ciphertext);

    Ok(output)
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

pub fn nonce_from_vec_small(sss: &Vec<u8>) -> [u8; NONCE_LEN_SMALL] {
    let mut array = [0u8; NONCE_LEN_SMALL];
    for index in 0..sss.len() {
        if index < NONCE_LEN_SMALL {
            array[index] = sss[index]
        }
    }

    return array;
}

pub fn nonce_from_vec_large(sss: &Vec<u8>) -> [u8; NONCE_LEN_LARGE] {
    let mut array = [0u8; NONCE_LEN_LARGE];
    for index in 0..sss.len() {
        if index < NONCE_LEN_LARGE {
            array[index] = sss[index]
        }
    }

    return array;
}

#[cfg_attr(test, allow(dead_code))]
#[cfg(test)]

mod tests {
    use super::{decrypt_small_file, encrypt_small_file};

    const INPUT_PATH: &str = "/xxx/next-14.1.0.tgz";
    const OUTPUT_PATH: &str = "/xxx/next-14.1.0.tgz.enc";
    const REOUT_PATH: &str = "/xxx/next-14.1.0.___.tgz";
    const KEY: [u8; 32] = [
        5, 5, 15, 47, 60, 61, 87, 90, 94, 99, 104, 115, 116, 118, 128, 130, 137, 138, 151, 162,
        165, 169, 174, 179, 191, 196, 214, 218, 223, 233, 249, 254,
    ];
    const NONCE: [u8; 24] = [
        1, 25, 33, 36, 36, 62, 62, 77, 84, 85, 89, 90, 91, 100, 113, 156, 168, 203, 212, 218, 243,
        246, 247, 254,
    ];

    #[test]
    pub fn test_small_file() -> Result<(), Box<dyn std::error::Error>> {
        encrypt_small_file(INPUT_PATH, OUTPUT_PATH, &KEY, &NONCE)?;
        decrypt_small_file(OUTPUT_PATH, REOUT_PATH, &KEY, &NONCE)?;

        Ok(())
    }
}
