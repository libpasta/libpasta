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
use ring::{digest, hkdf, hmac, rand};
use ring::rand::SecureRandom;
use serde_mcf;
use serde_yaml;

use super::HashUpdate;
use key;
use errors::*;
use hashing::{Algorithm, Output};
use primitives::{self, Primitive};
use sod::Sod;

use std::default::Default;
use std::fs::File;
use std::marker::{Send, Sync};
use std::path::Path;
use std::io::BufReader;
use std::sync::{Arc, Mutex};

static RAND_REF: &'static (SecureRandom + Send + Sync) = &rand::SystemRandom;
lazy_static! {
    /// Global source of randomness for generating salts
    pub static ref RANDOMNESS_SOURCE: Sod<SecureRandom + Send + Sync> = {
        lazy_static::initialize(&RAND_BACKUP);
        Sod::Static(RAND_REF)
    };

    /// Backup PRNG source for when `SystemRandom`is unavailable
    static ref RAND_BACKUP: Arc<Mutex<BackupPrng>> = {
        let rng = rand::SystemRandom::new();
        let mut seed = [0_u8; 32];
        rng.fill(&mut seed).expect("could not generate any randomness");
        Arc::new(Mutex::new(BackupPrng {
            salt: hmac::SigningKey::generate(&digest::SHA256, &rng).expect("could not generate any randomness"),
            seed: seed,
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

/// Configuration presets
pub enum Presets {
    /// The defaults used, useful to make small tweaks to the default set
    Default,
    /// Suitable values for interactive logins (~0.5s hashing times)
    Interactive,
    /// Stronger values for non-interactive actions, e.g. disk encryption (~3s hashing times)
    NonInteractive,
    /// Combines both `Argon2i` and `scrypt` for side-channel resistance.
    Paranoid,
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
    keys: &'static key::Store,
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


impl Config {
    /// Create a new empty `Config` for setting parameters.
    pub fn with_primitive(primitive: Primitive) -> Self {
        Self {
            algorithm: Algorithm::Single(primitive.clone()),
            primitive: primitive,
            keyed: None,
            keys: key::get_global(),
        }
    }

    /// Generates a `Config` from a selected preset
    /// configuration.
    pub fn from_preset(preset: &Presets) -> Self {
        match *preset {
            Presets::Default => Self::default(),
            Presets::Interactive => unimplemented!(),
            Presets::NonInteractive => unimplemented!(),
            Presets::Paranoid => unimplemented!(),
        }
    }

    /// Generates a `Config` from a .toml file.
    /// Config files can be generated using the `Config::to_string` method on 
    /// an existing config.
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
    pub fn hash_password(&self, password: &str) -> String {
        self.hash_password_safe(password).expect_report("failed to hash password")
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
        self.verify_password_update_hash_safe(hash, password).unwrap_or(HashUpdate::Failed)
    }

    /// Same as `verify_password_update_hash`, but returns `Result` to allow error handling.
    #[doc(hidden)]
    pub fn verify_password_update_hash_safe(&self, hash: &str, password: &str) -> Result<HashUpdate> {
        let pwd_hash: Output = serde_mcf::from_str(hash)?;
        if pwd_hash.verify(password) {
            if pwd_hash.alg != self.algorithm {
                let new_hash = serde_mcf::to_string(&self.algorithm.hash(password))?;
                Ok(HashUpdate::Verified(Some(new_hash)))
            } else {
                Ok(HashUpdate::Verified(None))
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
    pub fn migrate_hash(&self, hash: &str) -> Option<String> {
        self.migrate_hash_safe(hash).expect("failed to migrate password")
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
            Algorithm::Single(_) => Algorithm::Single(primitive.clone()),
            Algorithm::Nested { ref outer, .. } => Algorithm::Single(primitive).into_wrapped(outer.clone())
        };
    }

    /// Set a keyed function to be applied after hashing.
    pub fn set_keyed_hash(&mut self, keyed: Primitive) {
        self.keyed = Some(keyed.clone());
        let mut newalg = match self.algorithm {
            // If just a single algorithm, wrap with the keyed primitive
            Algorithm::Single(_) => self.algorithm.to_wrapped(keyed),
            // Otherwise, replace the outer algorithm with the keyed primitive
            Algorithm::Nested { outer: ref _outer, ref inner } => inner.to_wrapped(keyed)
        };
        newalg.update_key(self);
        self.algorithm = newalg;
    }

    /// Sets the location of keys for keyed functions.
    pub fn set_key_source(&mut self, store: &'static key::Store) {
        self.keys = store;
    }


    /// Serialize the configuration as YAML
    pub fn to_string(&self) -> String {
        serde_yaml::to_string(&self).expect("failed to serialize config")
    }
}

struct BackupPrng {
    salt: hmac::SigningKey,
    seed: [u8; 32],
}

impl BackupPrng {
    fn gen_salt(&mut self) -> Vec<u8> {
        let mut output = vec![0_u8; 48];
        hkdf::extract_and_expand(
            &self.salt,
            &self.seed,
            b"libpasta backup PRNG",
            &mut output
        );
        self.seed.copy_from_slice(&output[16..]);
        output.truncate(16);
        output
    }
}

pub(crate) fn backup_gen_salt() -> Vec<u8> {
    RAND_BACKUP.lock().expect("could not acquire lock on RAND_BACKUP").gen_salt()
}


#[cfg(test)]
mod test {
    use super::*;
    use super::super::*;

    use ring;
    #[test]
    fn use_config() {
        let config = Config::with_primitive(primitives::Argon2::default());
        let hash = config.hash_password("hunter2".into());
        assert!(config.verify_password(&hash, "hunter2".into()));

        let mut config = Config::default();
        config.set_primitive(primitives::Bcrypt::default());
        let hash = config.hash_password("hunter2".into());
        assert!(verify_password(&hash, "hunter2".into()));
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
        let hmac = primitives::Hmac::with_key_id(&ring::digest::SHA256, "dummy");
        config.set_keyed_hash(hmac);
        let hash = config.hash_password("hunter2");
        assert!(config.verify_password_safe(&hash, "hunter2").unwrap())
    }
}
