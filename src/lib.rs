// Copyright (c) 2017, Sam Scott

// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.

// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
// REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
// AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
// INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
// LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
// OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
// PERFORMANCE OF THIS SOFTWARE.

//! # Pasta - Password Storage
//! _Making passwords painless_
//!
//! This is a library designed to make secure password storage easy.
//!
//! For a more comprehensive introduction, see [the homepage](https://libpasta.github.io/)
//!
//!
//! ## Examples
//!
//! The basic functionality for computing password hashes is:
//!
//! ```
//! extern crate libpasta;
//! // We re-export the rpassword crate for CLI password input.
//! use libpasta::rpassword::*;
//!
//! fn main() {
//!     # if false {
//!     let password = prompt_password_stdout("Please enter your password:").unwrap();
//!     # }
//!     # let password = "hunter2".to_string();
//!     let password_hash = libpasta::hash_password(password);
//!     println!("The stored password is: '{}'", password_hash);
//! }
//! ```
//! ## Supported formats
//!
//! `libpasta` attempts to support some legacy formats. For example, the `bcrypt`
//! format `$2y$...`.

#![cfg_attr(all(feature="bench", test), feature(test))]


#![allow(unknown_lints)]
#![deny(clippy_pedantic)]
#![allow(
    missing_docs_in_private_items, 
    // we use fn new() -> Primitive for convenience
    new_ret_no_self, 
    range_plus_one, // `..=end` not yet stable
    use_debug,
)]
#![deny(
    const_err,
    dead_code,
    deprecated,
    exceeding_bitshifts,
    improper_ctypes,
    missing_docs,
    mutable_transmutes,
    no_mangle_const_items,
    non_camel_case_types,
    non_shorthand_field_patterns,
    non_snake_case,
    non_upper_case_globals,
    overflowing_literals,
    path_statements,
    plugin_as_library,
    private_no_mangle_fns,
    private_no_mangle_statics,
    stable_features,
    trivial_casts,
    trivial_numeric_casts,
    unconditional_recursion,
    unknown_crate_types,
    unreachable_code,
    unsafe_code,
    unstable_features,
    unused_allocation,
    unused_assignments,
    unused_attributes,
    unused_comparisons,
    unused_extern_crates,
    unused_features,
    unused_imports,
    unused_import_braces,
    unused_must_use,
    unused_mut,
    unused_parens,
    unused_qualifications,
    unused_results,
    unused_unsafe,
    unused_variables,
    variant_size_differences,
    warnings,
    while_true,
)]
#![cfg_attr(all(feature="bench", test), allow(unstable_features))]

extern crate clear_on_drop;
extern crate data_encoding;
#[macro_use]
extern crate error_chain;
extern crate itertools;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
extern crate num_traits;
extern crate ring;
extern crate ring_pwhash;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_mcf;
extern crate serde_yaml;

/// Re-export rpassword for convenience.
pub mod rpassword {
    extern crate rpassword;
    pub use self::rpassword::*;
}

/// `libpasta` errors.
pub mod errors {
    use ring;
    use serde_mcf;
    use std::{fmt, result};
    // Create the Error, ErrorKind, ResultExt, and Result types
    error_chain!{
        foreign_links {
            Deserialize(serde_mcf::errors::Error) #[doc = "Errors from de/serializing MCF password hashes."] ;
            Ring(ring::error::Unspecified) #[doc = "Errors originating from `ring`"] ;
        }
    }

    /// Convenience trait for producing detailed error messages on `expect`.
    pub trait ExpectReport {
        /// Return type on successful `expect`
        type Inner;
        /// Wraps `Result::expect` to produce a longer error message with
        /// instructions for submitting a bug report.
        fn expect_report(self, msg: &str) -> Self::Inner;
    }

    impl<T, E: fmt::Debug> ExpectReport for result::Result<T, E>  {
        type Inner = T;
        fn expect_report(self, msg: &str) -> T  {
            self.expect(&format!("{}\nIf you are seeing this message, you have encountered \
                a situation we did not think was possible. Please submit a bug \
                report at https://github.com/libpasta/libpasta/issues with this message.\n", msg))
        }
    }

    impl<T> ExpectReport for Option<T>  {
        type Inner = T;
        fn expect_report(self, msg: &str) -> T  {
            self.expect(&format!("{}\nIf you are seeing this message, you have encountered\
                a situation we did not think was possible. Please submit a bug\
                report at https://github.com/libpasta/libpasta/issues with this message.\n", msg))
        }
    }
}

use errors::*;

use clear_on_drop::ClearOnDrop;
use ring::rand::SecureRandom;

#[macro_use]
mod bench;

pub mod config;
pub use config::Config;
pub mod key;
pub mod hashing;
use hashing::Output;

pub mod primitives;

/// Module to define the Static or Dynamic `Sod` enum.
pub mod sod;

/// A simple wrapper for a password to denote it is a cleartext password.
/// Using `ClearOnDrop` attempts to clear the memory on drop.
pub struct Cleartext(ClearOnDrop<Vec<u8>>);

impl From<String> for Cleartext {
    fn from(thing: String) -> Self {
        Cleartext(ClearOnDrop::new(thing.into_bytes()))
    }
}

/// Generates a default hash for a given password.
///
/// Will automatically generate a random salt. In the extreme case that the
/// default source of randomness is unavailable, this will fallback to a seed
/// generated when the library is initialised. An error will be logged when this
/// happens.
///
/// This is the simplest way to use libpasta, and uses sane defaults.
/// ## Panics
/// A panic indicates a problem with the serialization mechanisms, and should
/// be reported.
pub fn hash_password(password: String) -> String {
    config::DEFAULT_CONFIG.hash_password(password)
}

/// Same as `hash_password` but returns `Result` to allow error handling.
/// TODO: decide on which API is best to use.
#[doc(hidden)]
pub fn hash_password_safe(password: String) -> Result<String> {
    config::DEFAULT_CONFIG.hash_password_safe(password)

}

/// Verifies the provided password matches the inputted hash string.
///
/// If there is any error in processing the hash or password, this
/// will simply return `false`.
pub fn verify_password(hash: &str, password: String) -> bool {
    verify_password_safe(hash, password).unwrap_or(false)
}

/// Same as `verify_password` but returns `Result` to allow error handling.
/// TODO: decide on which API is best to use.
#[doc(hidden)]
pub fn verify_password_safe(hash: &str, password: String) -> Result<bool> {
    let pwd_hash: Output = serde_mcf::from_str(hash)?;
    Ok(pwd_hash.verify(&password.into()))
}

/// Verifies a supplied password against a previously computed password hash,
/// and performs an in-place update of the hash value if the password verifies.
/// Hence this needs to take a mutable `String` reference.
pub fn verify_password_update_hash(hash: &mut String, password: String) -> bool {
    config::DEFAULT_CONFIG.verify_password_update_hash(hash, password)
}

/// Same as `verify_password_update_hash`, but returns `Result` to allow error handling.
#[doc(hidden)]
pub fn verify_password_update_hash_safe(hash: &mut String, password: String) -> Result<bool> {
    config::DEFAULT_CONFIG.verify_password_update_hash_safe(hash, password)

}


/// Migrate the input hash to the current recommended hash.
///
/// Note that this does *not* require the password. This is for batch updating
/// of hashes, where the password is not available. This performs an onion
/// approach, returning `new_hash(old_hash)`.
///
/// If the password is also available, the `verify_password_update_hash` should
/// instead be used.
pub fn migrate_hash(hash: &mut String) {
    config::DEFAULT_CONFIG.migrate_hash(hash)
}

/// Same as `migrate_hash` but returns `Result` to allow error handling.
#[doc(hidden)]
pub fn migrate_hash_safe(hash: &mut String) -> Result<()> {
    config::DEFAULT_CONFIG.migrate_hash_safe(hash)

}

fn gen_salt(rng: &SecureRandom) -> Vec<u8> {
    let mut salt = vec![0_u8; 16];
    if rng.fill(&mut salt).is_ok() {
        salt
    } else {
        error!("failed to get fresh randomness, relying on backup seed to generate pseudoranom output");
        config::backup_gen_salt()
    }
}

#[cfg(test)]
use ring::rand::SystemRandom;

#[cfg(test)]
fn get_salt() -> Vec<u8> {
    gen_salt(&SystemRandom)
}

#[cfg(test)]
mod api_tests {
    use super::*;
    use config::DEFAULT_PRIM;
    use hashing::{Algorithm, Output};
    use primitives::{Bcrypt, Hmac};
    use sod::Sod;

    #[test]
    fn sanity_check() {
        let password = "".to_owned();
        let hash = hash_password(password);
        println!("Hash: {:?}", hash);

        // can't use password again
        let password = "".to_owned();
        assert!(verify_password(&hash, password));
        assert!(!verify_password(&hash, "wrong password".to_owned()));

        let password = "hunter2".to_owned();
        let hash = hash_password(password);

        // can't use password again
        let password = "hunter2".to_owned();
        assert!(verify_password(&hash, password));
        assert!(!verify_password(&hash, "wrong password".to_owned()));
    }

    #[test]
    fn external_check() {
        let password = "hunter2".to_owned();
        let hash = "$2a$10$u.Fhlm/a1DpHr/z5KrsLG.iZ7iM9r8DInJvZ57VArRKuhlHAoVZOi";
        let pwd_hash: Output = serde_mcf::from_str(hash).unwrap();
        println!("{:?}", pwd_hash);

        let expected_hash = pwd_hash.alg.hash_with_salt(password.as_bytes(), &pwd_hash.salt);
        assert_eq!(pwd_hash.hash, &expected_hash[..]);
        assert!(verify_password(&hash, password));
    }

    #[test]
    fn emoji_password() {
        let password = "emojisaregreat💖💖💖".to_owned();
        let hash = hash_password(password.clone().into());
        assert!(verify_password(&hash, password.into()));
    }

    #[test]
    fn nested_hash() {
        let password = "hunter2".to_owned();

        let params = Algorithm::Nested {
            inner: Box::new(Algorithm::default()),
            outer: DEFAULT_PRIM.clone(),
        };
        let hash = params.hash(&password.into());

        let password = "hunter2".to_owned();
        println!("{:?}", hash);
        assert!(hash.verify(&password.into()));

        let password = "hunter2".to_owned();
        let hash = serde_mcf::to_string(&hash).unwrap();
        println!("{:?}", hash);
        let _hash: Output = serde_mcf::from_str(&hash).unwrap();
        println!("{:?}", _hash);
        assert!(verify_password(&hash, password));
    }

    #[test]
    fn verify_update() {
        let password = "hunter2".to_owned();

        let params = Algorithm::Nested {
            inner: Box::new(Algorithm::default()),
            outer: DEFAULT_PRIM.clone(),
        };
        let hash = params.hash(&password.into());

        let password = "hunter2".to_owned();
        assert!(hash.verify(&password.into()));

        let password = "hunter2".to_owned();
        let hash = serde_mcf::to_string(&hash).unwrap();
        assert!(verify_password(&hash, password));
    }

    #[test]
    fn migrate() {
        let password = "hunter2".to_owned();

        let params = Algorithm::Single(Bcrypt::default());
        let mut hash = serde_mcf::to_string(&params.hash(&password.into())).unwrap();
        println!("Original: {:?}", hash);
        migrate_hash(&mut hash);
        println!("Migrated: {:?}", hash);

        let password = "hunter2".to_owned();
        assert!(verify_password(&hash, password));

        let password = "hunter2".to_owned();
        assert!(verify_password_update_hash(&mut hash, password));
        println!("Updated: {:?}", hash);


        let password = "hunter2".to_owned();
        let mut pwd_hash: Output = serde_mcf::from_str(&hash).unwrap();
        pwd_hash.alg = Algorithm::default();
        assert!(pwd_hash.verify(&password.into()));
    }

    #[test]
    fn handles_broken_hashes() {
        // base hash: $$scrypt$ln=14,r=8,p=1$Yw/fI4D7b2PNqpUCg5UzKA$kp6humqf/GUV+6HQ/jND3gd8Zoz4VyBgGqk4DHt+k5c
        let password = "hunter2".to_owned();

        // Missing param
        let hash = "$$scrypt$ln=14p=1$Yw/fI4D7b2PNqpUCg5UzKA$kp6humqf/GUV+6HQ/jND3gd8Zoz4VyBgGqk4DHt+k5c";
        assert!(!verify_password(&hash, password.clone()));

        // Incorrect hash-id
        let hash = "$$nocrypt$ln=14p=1$Yw/fI4D7b2PNqpUCg5UzKA$kp6humqf/GUV+6HQ/jND3gd8Zoz4VyBgGqk4DHt+k5c";
        assert!(!verify_password(&hash, password.clone()));

        // Missing salt
        let hash = "$$scrypt$ln=14p=1$$kp6humqf/GUV+6HQ/jND3gd8Zoz4VyBgGqk4DHt+k5c";
        assert!(!verify_password(&hash, password.clone()));

        // Incorrect number of fields
        let hash = "$$scrypt$ln=14p=1$kp6humqf/GUV+6HQ/jND3gd8Zoz4VyBgGqk4DHt+k5c";
        assert!(!verify_password(&hash, password.clone()));

        // Truncated hash
        let hash = "$$scrypt$ln=14,r=8,\
                    p=1$Yw/fI4D7b2PNqpUCg5UzKA$kp6humqf/GUV+6HQ/jND3gd8Zoz4VyBgGqk4DHt";
        assert!(!verify_password(&hash, password.clone()));

        // Extended hash
        let hash = "$$scrypt$ln=14,r=8,\
                    p=1$Yw/fI4D7b2PNqpUCg5UzKA$kp6humqf/GUV+6HQ/jND3gd8Zoz4VyBgGqk4DHt+k5cAAAA";
        assert!(!verify_password(&hash, password.clone()));
    }

    #[test]
    fn migrate_hash_ok() {
        let mut hash = "$2a$10$175ikf/E6E.73e83.fJRbODnYWBwmfS0ENdzUBZbedUNGO.99wJfa".to_owned();
        migrate_hash(&mut hash);
    }

    #[test]
    fn hash_and_key() {
        let password = "hunter2".to_owned();

        let alg = Algorithm::Single(Bcrypt::default()).into_wrapped(Hmac::default().into());
        let hash = serde_mcf::to_string(&alg.hash(&password.clone().into())).unwrap();
        assert!(verify_password(&hash, password));
    }

    use std::result;
    use std::marker::{Send, Sync};

    struct NoRandomness;
    static NO_RAND_REF: &'static (SecureRandom + Send + Sync) = &NoRandomness;
    impl SecureRandom for NoRandomness {
        fn fill(&self, _dest: &mut [u8]) -> result::Result<(), ring::error::Unspecified> {
            Err(ring::error::Unspecified)
        }
    }

    #[test]
    fn no_randomness_ok() {
        use std::mem;

        // Using a broken PRNG still results in distinct salts
        let salt1 = ::gen_salt(&NoRandomness);
        let salt2 = ::gen_salt(&NoRandomness);
        assert!(salt1 != salt2);


        #[allow(unsafe_code)]
        unsafe {
            // We break the PRNG by replacing it with one which always fails!
            let rng = mem::transmute::<*const Sod<SecureRandom + Send + Sync>, *mut Sod<SecureRandom + Send + Sync>>(&*config::RANDOMNESS_SOURCE);
            *rng = Sod::Static(NO_RAND_REF);
        }

        // Yet two passwords differ
        let hash1 = hash_password("hunter2".to_owned());
        let hash2 = hash_password("hunter2".to_owned());
        assert!(hash1 != hash2);
    }
}
