//! # Configuration
//!
//! Included here are methods to setup and configure `libpasta`.
//! Currently, this refers to the choice of default hashing algorithm.
//!
//! Configuration can be specified in two ways: through configuration files,
//! or programmatically.
//!
//! Alternatively, the `set_primitive` function, and others, can be used
//! to configure the library. However, note that once the library is "in use",
//! i.e. a function like `hash_password` has been called, then attempting
//! to configure the library will cause a panic.
//!
//! There are a number of ways panics can happen through using the configuration
//! files. `libpasta` does not try to recover gracefully if
use lazy_static;
use ring::rand::SecureRandom;
use ring::{hkdf, rand};
use serde_mcf;
use serde_yaml;

use super::HashUpdate;
use errors::{ExpectReport, Result};
use hashing::{Algorithm, Output};
use key;
use primitives::{self, Primitive};

use std::default::Default;
use std::fmt;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::{Arc, Mutex};

lazy_static! {
    /// Global source of randomness for generating salts
    pub static ref RANDOMNESS_SOURCE: rand::SystemRandom = {
        lazy_static::initialize(&RAND_BACKUP);
        rand::SystemRandom::new()
    };

    /// Backup PRNG source for when `SystemRandom` is unavailable
    static ref RAND_BACKUP: Arc<Mutex<BackupPrng>> = {
        let rng = rand::SystemRandom::new();
        let mut seed = [0_u8; 32];
        let mut salt_key_value = [0_u8; 32];
        rng.fill(&mut seed).expect("could not generate any randomness");
        rng.fill(&mut salt_key_value).expect("could not generate any randomness");
        Arc::new(Mutex::new(BackupPrng {
            salt: hkdf::Salt::new(hkdf::HKDF_SHA256, &salt_key_value[..]),
            seed,
        }))
    };

    /// Default primitive used for hash computations
    pub static ref DEFAULT_PRIM: Primitive = {
        primitives::Scrypt::default()
    };

    /// Default algorithm to use for new hash computations.
    pub static ref DEFAULT_ALG: Algorithm = {
        Algorithm::Single(DEFAULT_PRIM.clone())
    };

    /// Default configuration set.
    pub static ref DEFAULT_CONFIG: Config = {
        Config::default()
    };
}

/// Holds possible configuration options
/// See the [module level documentation](index.html) for more information.
#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    #[serde(skip)]
    algorithm: Algorithm,
    #[serde(default = "primitives::Scrypt::default")]
    primitive: Primitive,
    keyed: Option<Primitive>,
    #[serde(skip, default = "key::get_global")]
    keys: &'static dyn key::Store,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            algorithm: DEFAULT_ALG.clone(),
            primitive: DEFAULT_PRIM.clone(),
            keyed: None,
            keys: key::get_global(),
        }
    }
}

impl fmt::Display for Config {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&serde_yaml::to_string(&self).map_err(|_| fmt::Error)?)
    }
}

impl Config {
    /// Create a new empty `Config` for setting parameters.
    #[must_use]
    pub fn with_primitive(primitive: Primitive) -> Self {
        Self {
            algorithm: Algorithm::Single(primitive.clone()),
            primitive,
            keyed: None,
            keys: key::get_global(),
        }
    }

    /// Generates a `Config` from a .toml file.
    /// Config files can be generated using the `Config::to_string` method on
    /// an existing config.
    ///
    /// # Errors
    ///
    /// If the config file could not be opened
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::open(path.as_ref());
        if let Ok(file) = file {
            let reader = BufReader::new(file);
            let mut config: Self = serde_yaml::from_reader(reader).expect("invalid config file");
            config.algorithm = Algorithm::Single(config.primitive.clone());
            if let Some(kh) = config.keyed.clone() {
                config.algorithm = config.algorithm.into_wrapped(kh);
            }
            trace!("imported config as: {:?}", config);
            Ok(config)
        } else {
            info!("could not open config file {:?}: {:?}", path.as_ref(), file);
            Err("could not open config file".into())
        }
    }

    /// Generates hash for a given password.
    ///
    /// Will automatically generate a random salt. In the extreme case that the
    /// default source of randomness is unavailable, this will fallback to a seed
    /// generated when the library is initialised. An error will be logged when this
    /// happens.
    ///    /// ## Panics
    /// A panic indicates a problem with the serialization mechanisms, and should
    /// be reported.
    #[must_use]
    pub fn hash_password(&self, password: &str) -> String {
        self.hash_password_safe(password)
            .expect_report("failed to hash password")
    }

    /// Same as `hash_password` but returns `Result` to allow error handling.
    /// TODO: decide on which API is best to use.
    #[doc(hidden)]
    pub fn hash_password_safe(&self, password: &str) -> Result<String> {
        let pwd_hash = self.algorithm.hash(password);
        Ok(serde_mcf::to_string(&pwd_hash)?)
    }

    /// Verifies the provided password matches the inputted hash string.
    ///
    /// If there is any error in processing the hash or password, this
    /// will simply return `false`.
    #[must_use]
    pub fn verify_password(&self, hash: &str, password: &str) -> bool {
        self.verify_password_safe(hash, password).unwrap_or(false)
    }

    /// Same as `verify_password` but returns `Result` to allow error handling.
    /// TODO: decide on which API is best to use.
    #[doc(hidden)]
    pub fn verify_password_safe(&self, hash: &str, password: &str) -> Result<bool> {
        let mut pwd_hash: Output = serde_mcf::from_str(hash)?;
        pwd_hash.check_keys(self);
        Ok(pwd_hash.verify(password))
    }

    /// Verifies a supplied password against a previously computed password hash,
    /// and performs an in-place update of the hash value if the password verifies.
    /// Hence this needs to take a mutable `String` reference.
    pub fn verify_password_update_hash(&self, hash: &str, password: &str) -> HashUpdate {
        self.verify_password_update_hash_safe(hash, password)
            .unwrap_or(HashUpdate::Failed)
    }

    /// Same as `verify_password_update_hash`, but returns `Result` to allow error handling.
    #[doc(hidden)]
    pub fn verify_password_update_hash_safe(
        &self,
        hash: &str,
        password: &str,
    ) -> Result<HashUpdate> {
        let pwd_hash: Output = serde_mcf::from_str(hash)?;
        if pwd_hash.verify(password) {
            if pwd_hash.alg == self.algorithm {
                Ok(HashUpdate::Verified(None))
            } else {
                let new_hash = serde_mcf::to_string(&self.algorithm.hash(password))?;
                Ok(HashUpdate::Verified(Some(new_hash)))
            }
        } else {
            Ok(HashUpdate::Failed)
        }
    }

    /// Migrate the input hash to the current recommended hash.
    ///
    /// Note that this does *not* require the password. This is for batch updating
    /// of hashes, where the password is not available. This performs an onion
    /// approach, returning `new_hash(old_hash)`.
    ///
    /// If the password is also available, the `verify_password_update_hash` should
    /// instead be used.
    #[must_use]
    pub fn migrate_hash(&self, hash: &str) -> Option<String> {
        self.migrate_hash_safe(hash)
            .expect("failed to migrate password")
    }

    /// Same as `migrate_hash` but returns `Result` to allow error handling.
    #[doc(hidden)]
    pub fn migrate_hash_safe(&self, hash: &str) -> Result<Option<String>> {
        let pwd_hash: Output = serde_mcf::from_str(hash)?;

        if !pwd_hash.alg.needs_migrating(&self.primitive) {
            // no need to migrate
            return Ok(None);
        }

        let new_params = pwd_hash.alg.to_wrapped(self.primitive.clone());
        let new_salt = pwd_hash.salt;

        let new_hash = self.primitive.compute(&pwd_hash.hash, &new_salt);
        let new_hash = Output {
            alg: new_params,
            hash: new_hash,
            salt: new_salt,
        };

        Ok(Some(serde_mcf::to_string(&new_hash)?))
    }

    /// Add a new key into the list of configured keys
    #[must_use]
    pub fn add_key(&self, key: &[u8]) -> String {
        self.keys.insert(key)
    }

    pub(crate) fn get_key(&self, key_id: &str) -> Option<Vec<u8>> {
        self.keys.get_key(key_id)
    }

    /// Set the default primitive
    pub fn set_primitive(&mut self, primitive: Primitive) {
        self.primitive = primitive.clone();
        self.algorithm = match self.algorithm {
            Algorithm::Single(_) => Algorithm::Single(primitive),
            Algorithm::Nested { ref outer, .. } => {
                Algorithm::Single(primitive).into_wrapped(outer.clone())
            }
        };
    }

    /// Set a keyed function to be applied after hashing.
    pub fn set_keyed_hash(&mut self, keyed: Primitive) {
        self.keyed = Some(keyed.clone());
        let mut newalg = match self.algorithm {
            // If just a single algorithm, wrap with the keyed primitive
            Algorithm::Single(_) => self.algorithm.to_wrapped(keyed),
            // Otherwise, replace the outer algorithm with the keyed primitive
            Algorithm::Nested {
                outer: ref _outer,
                ref inner,
            } => inner.to_wrapped(keyed),
        };
        newalg.update_key(self);
        self.algorithm = newalg;
    }

    /// Sets the location of keys for keyed functions.
    pub fn set_key_source(&mut self, store: &'static dyn key::Store) {
        self.keys = store;
    }
}

struct BackupPrng {
    salt: hkdf::Salt,
    seed: [u8; 32],
}

impl BackupPrng {
    fn gen_salt(&mut self) -> Vec<u8> {
        let mut buf = [0_u8; 48];
        let alg = self.salt.algorithm();
        self.salt
            .extract(&self.seed)
            .expand(&[b"libpasta backup PRNG"], alg)
            .expect("expand failure")
            .fill(&mut buf[..])
            .expect("fill failure");
        self.seed.copy_from_slice(&buf[16..]);
        let mut output = Vec::with_capacity(16);
        output.extend_from_slice(&buf[0..16]);
        output
    }
}

pub(crate) fn backup_gen_salt() -> Vec<u8> {
    RAND_BACKUP
        .lock()
        .expect("could not acquire lock on RAND_BACKUP")
        .gen_salt()
}

#[cfg(test)]
mod test {
    #![allow(clippy::wildcard_imports)]
    use super::*;
    use crate::*;

    use ring;
    #[test]
    fn use_config() {
        let config = Config::with_primitive(primitives::Argon2::default());
        let hash = config.hash_password("hunter2");
        assert!(config.verify_password(&hash, "hunter2"));

        let mut config = Config::default();
        config.set_primitive(primitives::Bcrypt::default());
        let hash = config.hash_password("hunter2");
        assert!(verify_password(&hash, "hunter2"));
    }

    #[derive(Debug)]
    struct StaticSource(&'static [u8; 16]);

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
    static STATIC_SOURCE: StaticSource = StaticSource(b"ThisIsAStaticKey");

    #[test]
    fn alternate_key_source() {
        let mut config = Config::default();
        config.set_key_source(&STATIC_SOURCE);
        let id = config.add_key(&[]);
        assert_eq!(config.get_key(&id), Some(b"ThisIsAStaticKey".to_vec()));
        let hmac = primitives::Hmac::with_key_id(ring::hkdf::HKDF_SHA256, "dummy");
        config.set_keyed_hash(hmac);
        let hash = config.hash_password("hunter2");
        assert!(config.verify_password_safe(&hash, "hunter2").unwrap())
    }
}
