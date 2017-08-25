//! Configuration module
//!
//! Included here are methods to setup and configure `libpasta`.
//! Currently, this refers to the choice of default hashing algorithm.
//!
//! Configuration can be specified in two ways: through configuration files, 
//! or programmatically.
//!
//! Configuration files are either found in the current path
//! with the name `.libpasta.yaml`, or an alternative path can be specified
//! using the environment variable `LIBPASTA_CFG`.
//!
//! Alternatively, the `set_primitive` function, and others, can be used
//! to configure the library. However, note that once the library is "in use", 
//! i.e. a function like `hash_password` has been called, then attempting
//! to configure the library will cause a panic.
//!
//! There are a number of ways panics can happen through using the configuration
//! files. `libpasta` does not try to recover gracefully if 
use data_encoding;
use serde_yaml;
use lazy_static;

use key;
use key::Store;
use hashing::Algorithm;
use primitives::{self, Primitive, PrimitiveImpl, Sod};

use std::default::Default;
use std::env;
use std::fs::File;
use std::path::{Path,PathBuf};
use std::io::BufReader;
use std::sync::{Arc, Mutex};

/// Holds possible configuration options
#[derive(Debug, Deserialize, Serialize)]
struct GlobalDefaults {
    #[serde(default)]
    default: AlgorithmChoice,
    keyed: Option<Primitive>,
    keys: Option<Vec<Vec<u8>>>,
    primitive: Option<Primitive>,
    #[serde(skip)]
    finalised: bool,
}

#[derive(Debug, Deserialize, Serialize)]
enum AlgorithmChoice {
    Argon2i,
    Scrypt,
    Custom,
}

impl Default for AlgorithmChoice {
    fn default() -> Self {
        AlgorithmChoice::Scrypt
    }
}

impl Default for GlobalDefaults {
    fn default() -> Self {
        GlobalDefaults {
            default: AlgorithmChoice::default(),
            keyed: None,
            keys: None,
            primitive: None,
            finalised: false,
        }
    }
}

/// Adds the configuration specified in the supplied file to the global
/// configuration
pub fn from_file<P: AsRef<Path>>(path: P) {
    let mut config = PASTA_CONFIG.lock().expect("could not acquire lock on config");
    config.merge_file(path, true);
}

/// Set the default hashing primitive to be used
///
/// This will only work if no API calls have been previously made
///
/// # Panics
/// This will panic if `set_primitive` is called after hvaing already used
/// the API, e.g. by calling `hash_password`.
///
/// This is to avoid any races between setting config values and using them.
pub fn set_primitive(primitive: Primitive) {
    let mut config = PASTA_CONFIG.lock().expect("could not acquire lock on config");
    config.set_primitive(primitive);
}

/// Use an _additional_ keyed hash function or encryption scheme.
///
/// This will only work if no API calls have been previously made
///
/// # Panics
/// This will panic if `set_primitive` is called after hvaing already used
/// the API, e.g. by calling `hash_password`.
pub fn set_keyed_hash(primitive: Primitive) {
    let mut config = PASTA_CONFIG.lock().expect("could not acquire lock on config");
    config.set_keyed_hash(primitive);
}

/// Add a new key into the list of configured keys
pub fn add_key(key: &[u8]) {
    let mut global_config = PASTA_CONFIG.lock().expect("could not acquire lock on config");
    global_config.add_key(key);
}

/// Print the global configuration as a YAML-formatted string.
pub fn to_string() -> String {
    let global_config = PASTA_CONFIG.lock().expect("could not acquire lock on config");
    global_config.to_string()
}

impl GlobalDefaults {
    /// Create a new empty `GlobalDefaults` for setting parameters
    fn new() -> Self {
        GlobalDefaults{
            default: AlgorithmChoice::default(),
            keyed: None,
            keys: None,
            primitive: None,
            finalised: false,
        }
    }

    /// Add a new key into the list of configured keys
    fn add_key(&mut self, key: &[u8]) {
        if self.keys.is_none() {
            self.keys = Some(Vec::new());
        }

        if let Some(ref mut v) = self.keys {
            v.push(key.to_vec());
        }
    }

    /// Set the default primitive
    fn set_primitive(&mut self, primitive: Primitive) {
        if self.finalised {
            panic!("Attempted to redefine configuration paramater after using config.");
        }
        if primitive == primitives::Argon2::default() {
            self.default = AlgorithmChoice::Argon2i;
        } else if primitive == primitives::Scrypt::default() {
            self.default = AlgorithmChoice::Scrypt;
        } else {
            self.primitive = Some(primitive);
            self.default = AlgorithmChoice::Custom;
        }
    }

    /// Set a keyed function to be applied after hashing.
    fn set_keyed_hash(&mut self, keyed: Primitive) {
        if self.finalised {
            panic!("Attempted to redefine configuration paramater after using config.");
        }
        self.keyed = Some(keyed);
    }

    fn merge_file<P: AsRef<Path>>(&mut self, path: P, ow: bool) {
        let file = File::open(path.as_ref());
        if let Ok(file) = file {
            let reader = BufReader::new(file);
            let config = serde_yaml::from_reader(reader).expect("invalid config file");
            trace!("imported config as: {:?}", config);
            if ow {
                self.merge_override(config);
            } else {
                self.merge(config);
            }
        } else {
            info!("could not open config file {:?}: {:?}", path.as_ref(), file)

        }
    }

    fn merge(&mut self, other: GlobalDefaults) {
        if self.primitive.is_none(){
            if let Some(prim) = other.primitive {
                self.set_primitive(prim);
            }
        }
        if self.keyed.is_none(){
            if let Some(k) = other.keyed {
                self.set_keyed_hash(k);
            }
        }
    }

    fn merge_override(&mut self, other: GlobalDefaults) {
        if let Some(prim) = other.primitive {
            self.set_primitive(prim);
        }
        if let Some(k) = other.keyed {
            self.set_keyed_hash(k);
        }
    }

    fn finalize(&mut self) {
        if self.finalised {
            panic!("Cannot finalize configuration more than once.");
        }
        // Set remaining fields from default.
        self.merge(Self::default());
        if let Some(ref keys) = self.keys {
            for key in keys {
                key::KEY_STORE.insert(data_encoding::base64::encode_nopad(key.as_ref()), key.as_ref());
            }
        }
        self.finalised = true;
    }

    /// Serialize the configuration as YAML 
    fn to_string(&self) -> String {
        serde_yaml::to_string(&self).expect("failed to serialize config")
    }
}

fn finalize_global_config() {
    let config: &mut GlobalDefaults = &mut *PASTA_CONFIG.lock().expect("could not acquire lock on config");
    let mut path = PathBuf::from(".");
    if let Ok(new_path) = env::var("LIBPASTA_CFG") {
        path.push(new_path);
    }
    path.push(".libpasta.yaml");
    config.merge_file(path, false);
    trace!("Final config output:\n{}", config.to_string());
    config.finalize();
}

use std::mem;

lazy_static!{
    // Global-accessible, mutable configuration value.
    static ref PASTA_CONFIG: Arc<Mutex<GlobalDefaults>> = {
        Arc::new(Mutex::new(GlobalDefaults::new()))
    };

    // Container to hold the custom `Primitive` choice, set via `set_primitive`.
    static ref CUSTOM_PRIM_IMPL: Arc<Box<PrimitiveImpl + 'static>> = {
        let mut config = PASTA_CONFIG.lock().expect("could not acquire lock on config");

        if let Some(ref mut prim) = config.primitive {
            match mem::replace(prim, primitives::Argon2::default()) {
                Primitive(Sod::Dynamic(p)) => p,
                Primitive(Sod::Static(_)) => panic!("attempting to set custom primitive to static implementation"),
            }
        } else {
            Arc::new(Box::new(primitives::Poisoned))
        }
    };

    static ref CUSTOM_KEYED_IMPL: Option<Arc<Box<PrimitiveImpl + 'static>>> = {
        let mut config = PASTA_CONFIG.lock().expect("could not acquire lock on config");

        if let Some(ref mut prim) = config.keyed {
            use serde_mcf::Hashes::*;
            match mem::replace(prim, primitives::Argon2::default()) {
                Primitive(Sod::Dynamic(p)) => {
                    match p.hash_id() {
                        Hmac => {
                            Some(p)
                        },
                        _ => panic!("attempting to use non-keyed hash for outer layer keying"),
                    }
                },
                Primitive(Sod::Static(_)) => panic!("attempting to set custom primitive to static implementation"),
            }
        } else {
            None
        }
    };

    /// Globally-set default `Primitive`. Guaranteed to be a static reference
    /// to some `PrimitiveImpl`.
    /// Note that accessing this variable finalises the configuration state and
    /// further changes cannot be made.
    pub static ref DEFAULT_PRIM: Primitive = {
        finalize_global_config();
        // Makes sure the CUSTOM_PRIM_IMPL is initialised before acquiring the lock.
        lazy_static::initialize(&CUSTOM_PRIM_IMPL);
        match PASTA_CONFIG.lock().expect("could not acquire lock on config").default {
            AlgorithmChoice::Argon2i => {
                primitives::Argon2::default()
            },
            AlgorithmChoice::Scrypt => {
                primitives::Scrypt::default()
            },
            AlgorithmChoice::Custom => {
                Primitive(Sod::Static(&***CUSTOM_PRIM_IMPL))
            }
        }
    };

    /// Default algorithm to use for new hash computations.
    pub static ref DEFAULT_ALG: Algorithm = {
        if let Some(ref p) = *CUSTOM_KEYED_IMPL {
            Algorithm::Nested { outer: Primitive(Sod::Dynamic(p.clone())), inner: Box::new(Algorithm::Single(DEFAULT_PRIM.clone())) }
        } else {
            Algorithm::Single(DEFAULT_PRIM.clone())
        }
    };
}


#[cfg(test)]
mod test {
    use super::*;
    use super::super::hash_password;

    #[test] #[should_panic]
    fn late_config() {
        let _ = hash_password("hunter2".into());
        let primitive = primitives::Scrypt::default();
        set_primitive(primitive);
        let hash = hash_password("hunter2".into());
        assert!(hash.starts_with("$$scrypt"));
    }
}