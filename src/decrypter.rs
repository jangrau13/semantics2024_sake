use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use shuttle::rand::RngCore;


pub fn encrypt(key: &[u8; 32], plaintext: &str) -> (Vec<u8>, Vec<u8>) {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);

    // Generate a random nonce
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);

    // Encrypt the plaintext
    let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce), plaintext.as_bytes())
        .expect("encryption failure!");

    (ciphertext, nonce.to_vec())
}

pub fn decrypt(key: &[u8; 32], ciphertext: &[u8], nonce: &[u8; 12]) -> String {
    let key = Key::<Aes256Gcm>::from_slice(key); // 256-bit key
    let cipher = Aes256Gcm::new(key);

    // Decrypt the ciphertext
    let decrypted = cipher.decrypt(Nonce::from_slice(nonce), ciphertext)
        .expect("decryption failure!");

    String::from_utf8(decrypted).expect("invalid UTF-8")
}
