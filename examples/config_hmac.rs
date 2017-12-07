extern crate libpasta;
extern crate ring;

use ring::digest;

fn main() {
    // Use scrypt as the default inner hash
    let hash_primitive = libpasta::primitives::Scrypt::default();
    let mut config = libpasta::Config::with_primitive(hash_primitive);

    // Some proper way of getting a key
    let key = b"yellow submarine";
    let key_id = config.add_key(key);
    // Construct an HMAC instance and use this as the outer configuration
    let keyed_function = libpasta::primitives::Hmac::with_key_id(&digest::SHA256, &key_id);
    config.set_keyed_hash(keyed_function);

    let hash = config.hash_password("hunter2");
    println!("Computed hash: {:?}", hash);
    // Outputs:
    // Computed hash: "$!$hmac$key_id=LNMhDy...,h=SHA256$$scrypt$ln=14,r=8,p=1$ZJ5EY...$grlNA...."

    assert!(hash.starts_with("$!$hmac"));
    assert!(hash.contains("scrypt"));
}
