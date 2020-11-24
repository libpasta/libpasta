//! `Primitive` in `libpasta` refers to the raw hashing algorithms as
//! implemented in many libraries.
//!
//! The main algorithms here are re-exported for general use.
//! Each algorithm has a `new` and `default` function. The former can
//! be provided parameters and creates a new dynamic instance of that
//! parameter set. Whereas the latter refers to a statically referenced
//! parameter set.
//!
//! All implementations are wrapped in a `Primitive` struct,
//! which in effect works like a trait, since it derefs to a `PrimitiveImpl`.
//! This means that whether using a new or default parameter set, the overall
//! behaviour is equivalent.


/// `Argon2` implementations
///
/// Currently only a native Rust implementation through `argon2rs`.
mod argon2;
pub use self::argon2::Argon2;

/// `Bcrypt` implementations
///
/// Currently uses `rust_crypto`s `bcrypt` algorithm.
mod bcrypt;
pub use self::bcrypt::Bcrypt;

/// `HMAC` implementations
///
/// Uses `ring::hmac` to provide an HMAC implementation. Key must either be
/// passed using `Hmac::with_key` or will be generated randomly with `Hmac::new`.
/// Still need to consider the best way to maintain keys for an application.
/// Perhaps need some kind of "key service" module.
mod hmac;
pub use self::hmac::Hmac;

/// `PBKDF2` implementations.
///
/// Implementations are from both `ring` and the C `fastpbkdf2` implementations.
/// The latter is currently in use.
mod pbkdf2;
pub use self::pbkdf2::Pbkdf2;

/// `Scrypt` implementations.
///
/// Currently uses `ring_pwhash` for the implementation.
mod scrypt;
pub use self::scrypt::Scrypt;


use sod::Sod;

use config;

use num_traits;
use num_traits::FromPrimitive;
use ring::{constant_time, hkdf};
use serde_mcf::{Hashes, Map, Value};

use std::cmp::Ordering;
use std::fmt;
use std::ops::Deref;
use std::sync::Arc;

/// Password hashing primitives
///
/// Each variant is backed up by different implementation.
/// Internally, primitives can either be static values, for example,
/// the `lazy_static` generated value `DEFAULT_PRIM`, or dynamically allocated
/// variables, which are `Arc<Box<...>>`.
///
/// Most operations are expected to be performed using the static functions,
/// since most use the default algorithms. However, the flexibilty to support
/// arbitrary parameter sets is essential.
#[derive(Clone, PartialEq, PartialOrd)]
pub struct Primitive(pub Sod<PrimitiveImpl>);


impl fmt::Debug for Primitive {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.0.deref())
    }
}
/// Trait defining the functionality of a hashing primitive.
pub trait PrimitiveImpl: fmt::Debug + Send + Sync {
    /// Compute the output of the primitive with input `password` and `salt`.
    fn compute(&self, password: &[u8], salt: &[u8]) -> Vec<u8>;

    /// Verify the password and salt against the hash.
    ///
    /// In many cases, this just checks whether
    /// `compute(password, salt) == hash`.
    fn verify(&self, password: &[u8], salt: &[u8], hash: &[u8]) -> bool {
        constant_time::verify_slices_are_equal(&self.compute(password, salt), hash).is_ok()
    }

    /// Output the parameters of the primitive as a list of tuples.
    fn params_as_vec(&self) -> Vec<(&'static str, String)>;

    /// Return algorithm type as a MCF-compatible hash identifier.
    fn hash_id(&self) -> Hashes;

    /// Use the supplied `Config` to update the current `Primitive` with
    /// a new key source.
    fn update_key(&self, _config: &config::Config) -> Option<Primitive> {
        None
    }
}

impl<P: PrimitiveImpl + 'static> From<P> for Primitive {
    fn from(other: P) -> Self {
        Primitive(Sod::Dynamic(Arc::new(Box::new(other))))
    }
}

impl PartialEq<PrimitiveImpl> for PrimitiveImpl {
    fn eq(&self, other: &PrimitiveImpl) -> bool {
        self.hash_id() == other.hash_id() && self.params_as_vec() == other.params_as_vec()
    }
}

/// Compare two primitive parameterisations by first checking for equality of
/// the hash identifiers, and then attempting to compare the parameters
/// numerically.
impl PartialOrd<PrimitiveImpl> for PrimitiveImpl {
    fn partial_cmp(&self, other: &PrimitiveImpl) -> Option<Ordering> {
        if self.hash_id() == other.hash_id() {
            self.params_as_vec()
                .iter()
                .zip(other.params_as_vec().iter())
                .map(|(x, y)| if x == y {
                    Some(Ordering::Equal)
                } else if x.0 != y.0 {
                    None
                } else if let Ok(x) = x.1.parse::<f64>() {
                    if let Ok(y) = y.1.parse::<f64>() {
                        x.partial_cmp(&y)
                    } else {
                        None
                    }
                } else {
                    None
                })
                .try_fold(None, |acc, c| if acc.is_none() {
                        Some(c)
                } else if c == acc || c == Some(Ordering::Equal) {
                        Some(acc)
                } else {
                        None
                })
                .unwrap_or(None)
        } else {
            None
        }
    }
}


impl Deref for Primitive {
    type Target = Sod<PrimitiveImpl>;

    fn deref(&self) -> &Sod<PrimitiveImpl> {
        &self.0
    }
}

#[derive(Debug, PartialEq, PartialOrd)]
pub(crate) struct Poisoned;

impl PrimitiveImpl for Poisoned {
    fn compute(&self, _password: &[u8], _salt: &[u8]) -> Vec<u8> {
        unreachable!()
    }

    fn verify(&self, _password: &[u8], _salt: &[u8], _hash: &[u8]) -> bool {
        unreachable!()
    }

    fn params_as_vec(&self) -> Vec<(&'static str, String)> {
        vec![("poisoned", "".to_string())]
    }

    fn hash_id(&self) -> Hashes {
        Hashes::Custom
    }
}

/// Helper macro to unwrap the value or early return with `Poisoned`.
/// Necessary until `TryFrom` stabilises.
macro_rules! try_or_poisoned {
    ($f:expr) => (
        match $f {
            Some(x) => x,
            None => return Poisoned.into()
        }
    )
}

/// This will be `TryFrom` when it stabilises.
/// For now we just return a `Poisoned`
impl<'a> From<(&'a Hashes, &'a Map<String, Value>)> for Primitive {
    fn from(other: (&Hashes, &Map<String, Value>)) -> Self {
        match *other.0 {
            Hashes::Argon2i | Hashes::Argon2d => {
                let passes = try_or_poisoned!(other.1.get("t").and_then(value_as_int));
                let lanes = try_or_poisoned!(other.1.get("p").and_then(value_as_int));
                let kib = try_or_poisoned!(other.1.get("m").and_then(value_as_int));
                Argon2::new(passes, lanes, kib)
            }
            Hashes::BcryptMcf => {
                let cost = try_or_poisoned!(other.1.get("cost").and_then(value_as_int));
                Bcrypt::new(cost)
            }
            Hashes::Hmac => {
                let hash_id = try_or_poisoned!(other.1.get("h").and_then(Value::as_str));
                let key_id = try_or_poisoned!(other.1.get("key_id").and_then(Value::as_str));
                Hmac::with_key_id(hash_from_id(hash_id), key_id)
            }
            ref x @ Hashes::Pbkdf2Sha1 |
            ref x @ Hashes::Pbkdf2Sha256 |
            ref x @ Hashes::Pbkdf2Sha512 => {
                let iterations = try_or_poisoned!(other.1.get("n").and_then(value_as_int));
                pbkdf2::Pbkdf2::new(iterations, match *x {
                    Hashes::Pbkdf2Sha1 => ring::pbkdf2::PBKDF2_HMAC_SHA1,
                    Hashes::Pbkdf2Sha256 => ring::pbkdf2::PBKDF2_HMAC_SHA256,
                    Hashes::Pbkdf2Sha512 => ring::pbkdf2::PBKDF2_HMAC_SHA512,
                    _ => return Poisoned.into() // not actually possible due to previous matching,
                })
            }
            Hashes::Scrypt => {
                let log_n = try_or_poisoned!(other.1.get("ln").and_then(value_as_int));
                let r = try_or_poisoned!(other.1.get("r").and_then(value_as_int));
                let p = try_or_poisoned!(other.1.get("p").and_then(value_as_int));
                Scrypt::new(log_n, r, p)
            }
            _ => Poisoned.into(),
        }
    }
}

fn value_as_int<T>(val: &Value) -> Option<T>
    where T: num_traits::Num + FromPrimitive
{
    match *val {
        Value::Number(ref x) => {
            if let Some(x) = x.as_u64() {
                T::from_u64(x)
            } else {
                None
            }
        }
        Value::String(ref s) => T::from_str_radix(s.as_str(), 10).ok(),
        _ => None,
    }
}

impl<'a> From<&'a Primitive> for (Hashes, Map<String, Value>) {
    fn from(other: &Primitive) -> Self {
        let mut map = Map::new();
        for (key, value) in other.0.params_as_vec() {
            let _ = map.insert(key.to_string(), Value::String(value));
        }
        (other.0.hash_id(), map)
    }
}

fn hash_to_id(algorithm: hkdf::Algorithm) -> String {
    match algorithm {
        a if a == hkdf::HKDF_SHA1_FOR_LEGACY_USE_ONLY => "SHA1",
        a if a == hkdf::HKDF_SHA256 => "SHA256",
        a if a == hkdf::HKDF_SHA384 => "SHA384",
        a if a == hkdf::HKDF_SHA512 => "SHA512",
        _ => panic!("Unknown digest algorithm"),
    }.to_owned()
}

fn hash_from_id(id: &str) -> hkdf::Algorithm {
    match id {
        "SHA1" => hkdf::HKDF_SHA1_FOR_LEGACY_USE_ONLY,
        "SHA256" => hkdf::HKDF_SHA256,
        "SHA384" => hkdf::HKDF_SHA384,
        "SHA512" => hkdf::HKDF_SHA512,
        _ => panic!("Unknown digest algorithm"),
    }
}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_comparisons() {
        let bcrypt = Bcrypt::new(10);
        let bcrypt_better = Bcrypt::new(20);

        let scrypt = Scrypt::new(10, 8, 1);
        let scrypt_better = Scrypt::new(14, 8, 1);
        let scrypt_diff = Scrypt::new(15, 4, 1);

        assert_eq!(bcrypt, bcrypt);
        assert_eq!(scrypt, scrypt);

        assert_eq!(bcrypt.partial_cmp(&bcrypt_better), Some(Ordering::Less));
        assert!(scrypt < scrypt_better);

        assert_eq!(scrypt.partial_cmp(&scrypt_diff), None);
        assert_eq!(scrypt_better.partial_cmp(&scrypt_diff), None);
        assert_eq!(scrypt.partial_cmp(&bcrypt), None);
    }
}
