//! The `key` module is for managing key sources.
//!
//! The idea is that a running application can dynamically insert keys into
//! the key store, which are used for producing and verifying hashes.
#![allow(dead_code)]

use data_encoding::base64;
use ring::digest;

use std::collections::HashMap;
use std::fmt;
use std::sync::RwLock;

lazy_static!{
    static ref LOCAL_STORE: LocalStore = LocalStore::new();
}

pub(crate) fn get_global() -> &'static LocalStore {
    &*LOCAL_STORE
}

/// Structure used as a global store for keys.
#[derive(Debug)]
pub struct LocalStore {
    store: RwLock<HashMap<String, Vec<u8>>>,
}


/// A key storage source. Permits retrieving and storing keys.
///
/// Keys are indexed by a `String` id, and are stored as Vec<u8>.
pub trait Store: fmt::Debug + Send + Sync {
    /// Insert a new key into the `Store`.
    fn insert(&self, key: &[u8]) -> String;

    /// Get a key from the `Store`.
    fn get_key(&self, id: &str) -> Option<Vec<u8>>;
}

impl LocalStore {
    fn new() -> Self {
        Self { store: RwLock::new(HashMap::new()) }
    }
}

impl Store for LocalStore {
    /// Insert a new key into the `KeyStore`.
    fn insert(&self, key: &[u8]) -> String {
        let digest = digest::digest(&digest::SHA512_256, key);
        let key_id = base64::encode_nopad(digest.as_ref());
        let _ = self.store
            .write()
            .expect("could not get write on key store")
            .insert(key_id.clone(), key.to_vec());
        key_id
    }

    /// Get a key from the `KeyStore`.
    fn get_key(&self, id: &str) -> Option<Vec<u8>> {
        if let Some(v) = self.store.read().expect("could not get read lock on key store").get(id) {
            Some(v.clone())
        } else {
            None
        }
    }
}
