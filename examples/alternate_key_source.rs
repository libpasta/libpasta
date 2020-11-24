extern crate libpasta;
extern crate ring;

use libpasta::key;
use ring::hkdf;

#[derive(Debug)]
struct StaticSource(&'static [u8; 16]);
static STATIC_SOURCE: StaticSource = StaticSource(b"ThisIsAStaticKey");

impl key::Store for StaticSource {
    /// Insert a new key into the `Store`.
    fn insert(&self, _key: &[u8]) -> String {
        "StaticKey".to_string()
    }

    /// Get a key from the `Store`.
    fn get_key(&self, _id: &str) -> Option<Vec<u8>> {
        Some(self.0.to_vec())
    }
}

fn main() {
    let mut config = libpasta::Config::default();
    config.set_key_source(&STATIC_SOURCE);

    // Construct an HMAC instance and use this as the outer configuration
    let keyed_function = libpasta::primitives::Hmac::with_key_id(hkdf::HKDF_SHA256, "StaticKey");
    config.set_keyed_hash(keyed_function);

    let hash = config.hash_password("hunter2");
    println!("Computed hash: {:?}", hash);
}
