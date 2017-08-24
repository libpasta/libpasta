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
pub use self::pbkdf2::{Pbkdf2, RingPbkdf2};

/// `Scrypt` implementations.
///
/// Currently uses `ring_pwhash` for the implementation.
mod scrypt;
pub use self::scrypt::Scrypt;

/// Module to define the Static or Dynamic `Sod` enum.
mod sod;
pub use self::sod::Sod;

use key::Store;

use num_traits;
use num_traits::FromPrimitive;
use ring::{constant_time, digest};
use serde_mcf::{Hashes, Map, Value};

use std::cmp::Ordering;
use std::fmt;
use std::fmt::Write;
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

impl PartialOrd<PrimitiveImpl> for PrimitiveImpl {
    fn partial_cmp(&self, other: &PrimitiveImpl) -> Option<Ordering> {
        if self.hash_id() == other.hash_id() {
            Some(self.params_as_vec().cmp(&other.params_as_vec()))
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

macro_rules! unwrap_or_default {
    ($default:expr, $var:expr,) => (
        $var
    );
    ($default:expr, $var:expr, r $code:expr, $($tail:tt,)*) => (
        if let Ok(x) = $code($var) {
            unwrap_or_default!($default, x, $($tail,)*)
        } else {
            return $default
        }
    );
    ($default:expr, $var:expr, o $code:expr, $($op:tt $tail:expr,)*) => (
        if let Some(x) = $code($var) {
            unwrap_or_default!($default, x, $($op $tail,)*)
        } else {
            return $default
        }
    );
}


#[derive(Debug, PartialEq, PartialOrd)]
pub(crate) struct Poisoned;

impl PrimitiveImpl for Poisoned {
    fn compute(&self, _password: &[u8], _salt: &[u8]) -> Vec<u8> {
        vec![]
    }

    fn verify(&self, _password: &[u8], _salt: &[u8], _hash: &[u8]) -> bool {
        false
    }

    fn params_as_vec(&self) -> Vec<(&'static str, String)> {
        vec![("poisoned", "".to_string())]
    }

    fn hash_id(&self) -> Hashes {
        Hashes::Custom
    }
}

/// This will be `TryFrom` when it stabilises. 
/// For now we just return a `Poisoned`
impl<'a> From<(&'a Hashes, &'a Map<String, Value>)> for Primitive {
    fn from(other: (&Hashes, &Map<String, Value>)) -> Self {
        match *other.0 {
            Hashes::Argon2i | Hashes::Argon2d => {
                let passes = unwrap_or_default!(
                    Poisoned.into(),
                    &other.1["t"],
                    o Value::as_str,
                    r |x| { u32::from_str_radix(x, 10) },
                );
                let lanes = unwrap_or_default!(
                    Poisoned.into(),
                    &other.1["p"],
                    o Value::as_str,
                    r |x| { u32::from_str_radix(x, 10) },
                );
                let kib = unwrap_or_default!(
                    Poisoned.into(),
                    &other.1["m"],
                    o Value::as_str,
                    r |x| { u32::from_str_radix(x, 10) },
                );
                Argon2::new(passes, lanes, kib)
            },
            Hashes::BcryptMcf => {
                let cost = unwrap_or_default!(
                    Poisoned.into(),
                    &other.1["cost"],
                    o Value::as_str,
                    r |x| { u32::from_str_radix(x, 10) },
                );
                Bcrypt::new(cost)
            },
            Hashes::Hmac => {
                let hash_id = unwrap_or_default!(
                    Poisoned.into(),
                    &other.1["h"],
                    o Value::as_str,
                );
                let key_id = unwrap_or_default!(
                    Poisoned.into(),
                    &other.1["key_id"],
                    o Value::as_str,
                );
                Hmac::with_key(hash_from_id(hash_id), &::key::KEY_STORE.get_key(key_id).expect("could not get key from store"))
            },
            ref x @ Hashes::Pbkdf2Sha1 | 
            ref x @ Hashes::Pbkdf2Sha256 | 
            ref x @ Hashes::Pbkdf2Sha512 => {
                let iterations = unwrap_or_default!(
                    Poisoned.into(),
                    &other.1["n"],
                    o Value::as_str,
                    r |x| { u32::from_str_radix(x, 10) },
                );
                match *x {
                    Hashes::Pbkdf2Sha1 => pbkdf2::Pbkdf2::new(iterations, &digest::SHA1),
                    Hashes::Pbkdf2Sha256 => pbkdf2::Pbkdf2::new(iterations, &digest::SHA256),
                    Hashes::Pbkdf2Sha512 => pbkdf2::Pbkdf2::new(iterations, &digest::SHA512),
                    _ => panic!("impossible due to previous matching"),
                }
            },
            Hashes::ScryptMcf => {
                let log_n = unwrap_or_default!(
                    Poisoned.into(),
                    &other.1["log_n"],
                    o value_as_int::<u8>,
                );
                let r = unwrap_or_default!(
                    Poisoned.into(),
                    &other.1["r"],
                    o value_as_int::<u32>,
                );
                let p = unwrap_or_default!(
                    Poisoned.into(),
                    &other.1["p"],
                    o value_as_int::<u32>,
                );
                Scrypt::new(log_n, r, p)
            },
            _ => {
                panic!("");
            }
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
        },
        Value::String(ref s) => T::from_str_radix(s.as_str(), 10).ok(),
        _ => None
    }
}

impl<'a> From<(&'a Hashes, &'a String)> for Primitive {
    fn from(other: (&Hashes, &String)) -> Self {
        use self::Hashes::*;
        if let BcryptMcf = *other.0 {
            let cost = u32::from_str_radix(other.1, 10).expect("parameter could not be parsed as an integer");
            bcrypt::Bcrypt::new(cost)
        } else {
            panic!("No suitable parameter format found");
        }
    }
}

impl<'a> From<(&'a Hashes, [u8; 9])> for Primitive {
    fn from(other: (&Hashes, [u8; 9])) -> Self {
        if let Hashes::Scrypt = *other.0 {
            scrypt::Scrypt::from_bytes(other.1)
        } else {
            panic!("No suitable parameter format found");
        }
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

fn hash_to_id(algorithm: &'static digest::Algorithm) -> String {
    let mut name = String::new();
    #[allow(use_debug)]
    write!(&mut name, "{:?}", algorithm).expect("error writing to String");
    name
}

fn hash_from_id(id: &str) -> &'static digest::Algorithm {
    match id {
        "SHA1" => &digest::SHA1,
        "SHA256" => &digest::SHA256,
        "SHA384" => &digest::SHA384,
        "SHA512" => &digest::SHA512,
        "SHA512_256" => &digest::SHA512_256,
        _ => panic!("Unknown digest algorithm"),
    }
}
