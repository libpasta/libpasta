//! Password hashing functionality
//!
//! While the `primitives` module handles the raw implementations of hashing
//! algorithms, this module contains the `libpasta` hashing functionality
//! itself. In particular, a `libpasta` hashing `Algorithm` is defined as a
//! recursive structure, containing either a single `Primitive`, or a
//! `Primitive` and a further layer of `Algorithm`. This is the hashing onion.

// use std::cmp::PartialOrd;
use std::default::Default;

use config;
use primitives::Primitive;
use super::Cleartext;

mod de;
mod ser;

#[derive(Clone, Debug, PartialEq)]
/// `libpasta` password hashing algorithms can be nested, which is captured
/// by this recursive enum.
pub enum Algorithm {
    /// A single instance of a password-hashing primitive.
    Single(Primitive),
    /// The password-hashing algorithm is composed of nested primitives.
    Nested {
        /// The outermost layer of the algorithm is a single primitive
        outer: Primitive,
        /// The rest of the layers
        inner: Box<Algorithm>,
    },
}


#[derive(Debug)]
/// Represents the output of a password hashing algorithm.
pub struct Output {
    /// The algorithm used
    pub alg: Algorithm,
    /// The salt
    pub salt: Vec<u8>,
    /// The hash output
    pub hash: Vec<u8>,
}


impl Default for Algorithm {
    fn default() -> Self {
        config::DEFAULT_ALG.clone()
    }
}

impl Output {
    /// Verifies that the supplied password matches the hashed value.
    pub fn verify(&self, password: Cleartext) -> bool {
        self.alg.verify(&password.0, &self.salt, &self.hash)
    }
}

impl Algorithm {
    /// Type-safe function to compute the hash of a password.
    pub fn hash(&self, password: Cleartext) -> Output {
        let salt = super::gen_salt(&**config::RANDOMNESS_SOURCE);
        let output = self.hash_with_salt(&password.0, &salt);
        Output {
            hash: output,
            salt: salt,
            alg: self.clone(),
        }
    }

    /// Computes the hash output for given password and salt.
    pub fn hash_with_salt(&self, password: &[u8], salt: &[u8]) -> Vec<u8> {
        match *self {
            Algorithm::Single(ref p) => p.compute(password, salt),
            Algorithm::Nested { ref inner, ref outer } => {
                let innerput = inner.hash_with_salt(password, salt);
                outer.compute(&innerput, salt)
            }
        }
    }

    /// Verifies the password, salt and hash are matching by recursively
    /// re-computing the hash and verifying the final value.
    pub fn verify(&self, password: &[u8], salt: &[u8], hash: &[u8]) -> bool {
        match *self {
            Algorithm::Single(ref p) => p.verify(password, salt, hash),
            Algorithm::Nested { ref inner, ref outer } => {
                let innerput = inner.hash_with_salt(password, salt);
                outer.verify(&innerput, salt, hash)
            }
        }
    }

    /// Test whether the current 'Algorithm` is sufficiently secure.
    pub fn needs_migrating(&self) -> bool {
        let default: &Primitive = &*config::DEFAULT_PRIM;

        match *self {
            Algorithm::Single(ref a2) |
            Algorithm::Nested { outer: ref a2, .. } => a2.ge(default),
        }
    }

    /// Copies `self` into a new `Algorithm` wrapped by `outer`
    pub fn to_wrapped(&self, outer: Primitive) -> Self {
        Algorithm::Nested {
            outer: outer,
            inner: Box::new(self.clone()),
        }
    }

    /// Moves `self` into a new `Algorithm` wrapped by `outer`
    pub fn into_wrapped(self, outer: Primitive) -> Self {
        Algorithm::Nested {
            outer: outer,
            inner: Box::new(self),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_mcf;

    #[test]
    fn test_hash() {
        let alg = Algorithm::default();
        let output = alg.hash("hunter2".to_string().into());
        println!("{:?}", serde_mcf::to_string(&output).unwrap());
    }

    #[test]
    fn test_wrapped() {
        let alg = Algorithm::default();
        let prim = &*config::DEFAULT_PRIM;
        let _alg1 = alg.to_wrapped(prim.clone());
        let _alg = alg.into_wrapped(prim.clone());
    }
}
