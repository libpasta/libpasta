//! Password hashing functionality
//!
//! While the `primitives` module handles the raw implementations of hashing
//! algorithms, this module contains the `libpasta` hashing functionality
//! itself. In particular, a `libpasta` hashing `Algorithm` is defined as a
//! recursive structure, containing either a single `Primitive`, or a
//! `Primitive` and a further layer of `Algorithm`. This is the hashing onion.

use serde_mcf;

use std::cmp::PartialOrd;
use std::default::Default;
use std::fmt;

use config;
use errors::*;
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
        self.hash == self.alg.hash_with_salt(&password.0, &self.salt)
    }
}

impl fmt::Display for Output {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Ok(s) = serde_mcf::to_string(self) {
            write!(f, "{}", s)
        } else {
            error!("could not format hash output as serde_mcf string");
            Err(fmt::Error::default())
        }
    }
}


impl Algorithm {
    /// Type-safe function to compute the hash of a password.
    pub fn hash(&self, password: Cleartext) -> Result<Output> {
        let salt = super::gen_salt()?;
        let output = self.hash_with_salt(&password.0, &salt);
        Ok(Output {
            hash: output,
            salt: salt,
            alg: self.clone(),
        })
    }

    /// Computes the hash output for given password and salt.
    pub fn hash_with_salt(&self, password: &[u8], salt: &[u8]) -> Vec<u8> {
        match *self {
            Algorithm::Single(ref p) => {
                p.compute(password, salt)
            },
            Algorithm::Nested { ref inner, ref outer } => {
                let innerput = inner.hash_with_salt(password, salt);
                outer.compute(&innerput, salt)
            }
        }
    }

    /// Test whether the current 'Algorithm` is sufficiently secure.
    ///
    /// TODO: Implement different ways to determine "secure".
    /// For now, this just checks you are using Argon2 with a decent memory 
    /// parameter.
    pub fn needs_migrating(&self) -> bool {
        let default: &Primitive = &*config::DEFAULT_PRIM;
        match *self {
            Algorithm::Single(ref a2) | Algorithm::Nested { outer: ref a2, ..  } => {
                a2.ge(default)
            }
        }
    }

    /// Copies `self` into a new `Algorithm` wrapped by `outer`
    pub fn to_wrapped(&self, outer: Primitive) -> Algorithm {
        Algorithm::Nested { outer, inner: Box::new(self.clone()) }
    }

    /// Moves `self` into a new `Algorithm` wrapped by `outer`
    pub fn into_wrapped(self, outer: Primitive) -> Algorithm {
        Algorithm::Nested { outer, inner: Box::new(self) }
    }
}

#[test]
fn test_hash() {
    let alg = Algorithm::default();
    let output = alg.hash("hunter2".to_string().into()).unwrap();
    // assert!(output);
    println!("{:?}", serde_mcf::to_string(&output).unwrap());
}
