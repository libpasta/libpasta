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
//!     # let password = "hunter2";
//!     let password_hash = libpasta::hash_password(password);
//!     println!("The stored password is: '{}'", password_hash);
//! }
//! ```
//! ## Supported formats
//!
//! `libpasta` attempts to support some legacy formats. For example, the `bcrypt`
//! format `$2y$...`.

#![allow(unknown_lints)]
#![deny(clippy::pedantic)]
#![allow(
    clippy::missing_docs_in_private_items, 
    // we use fn new() -> Primitive for convenience
    clippy::new_ret_no_self, 
    clippy::range_plus_one, // `..=end` not yet stable
)]
#![deny(
    const_err,
    dead_code,
    deprecated,
    arithmetic_overflow,
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
    stable_features,
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
    while_true,
)]
// Necessary for having benchmarks defined inline.
#![cfg_attr(all(feature="bench", test), feature(test))]
#![cfg_attr(all(feature="bench", test), allow(unstable_features))]

extern crate data_encoding;
#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
extern crate num_traits;
extern crate ring;
#[macro_use]
extern crate serde;
extern crate serde_mcf;
extern crate serde_yaml;

/// Re-export rpassword for convenience.
pub mod rpassword {
    extern crate rpassword;
    pub use self::rpassword::*;
}

/// `libpasta` errors.
#[allow(deprecated)]
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
            self.unwrap_or_else(|_| panic!("{}\nIf you are seeing this message, you have encountered \
                a situation we did not think was possible. Please submit a bug \
                report at https://github.com/libpasta/libpasta/issues with this message.\n", msg))
        }
    }

    impl<T> ExpectReport for Option<T>  {
        type Inner = T;
        fn expect_report(self, msg: &str) -> T  {
            self.unwrap_or_else(|| panic!("{}\nIf you are seeing this message, you have encountered\
                a situation we did not think was possible. Please submit a bug\
                report at https://github.com/libpasta/libpasta/issues with this message.\n", msg))
        }
    }
}

use errors::*;
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
pub fn hash_password(password: &str) -> String {
    config::DEFAULT_CONFIG.hash_password(password)
}

/// Same as `hash_password` but returns `Result` to allow error handling.
/// TODO: decide on which API is best to use.
#[doc(hidden)]
pub fn hash_password_safe(password: &str) -> Result<String> {
    config::DEFAULT_CONFIG.hash_password_safe(password)

}

/// Verifies the provided password matches the inputted hash string.
///
/// If there is any error in processing the hash or password, this
/// will simply return `false`.
pub fn verify_password(hash: &str, password: &str) -> bool {
    verify_password_safe(hash, password).unwrap_or(false)
}

/// Same as `verify_password` but returns `Result` to allow error handling.
/// TODO: decide on which API is best to use.
#[doc(hidden)]
pub fn verify_password_safe(hash: &str, password: &str) -> Result<bool> {
    let pwd_hash: Output = serde_mcf::from_str(hash)?;
    Ok(pwd_hash.verify(password))
}

/// On migrating a hash with the password entered, we reach three possible
/// states:
///   - Password verified, and the hash was migrated
///   - Password verified, but the hash did not need to be migrated
///   - Incorrect password (or other verification failure)
#[derive(Debug, PartialEq)]
pub enum HashUpdate {
    /// Password verification succeeded, with new string if migration was
    /// performed
    Verified(Option<String>),
    /// Password verification failed
    Failed,
}

/// Verifies a supplied password against a previously computed password hash,
/// and performs an in-place update of the hash value if the password verifies.
/// Hence this needs to take a mutable `String` reference.
pub fn verify_password_update_hash(hash: &str, password: &str) -> HashUpdate {
    config::DEFAULT_CONFIG.verify_password_update_hash(hash, password)
}

/// Same as `verify_password_update_hash`, but returns `Result` to allow error handling.
#[doc(hidden)]
pub fn verify_password_update_hash_safe(hash: &str, password: &str) -> Result<HashUpdate> {
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
pub fn migrate_hash(hash: &str) -> Option<String> {
    config::DEFAULT_CONFIG.migrate_hash(hash)
}

/// Same as `migrate_hash` but returns `Result` to allow error handling.
#[doc(hidden)]
pub fn migrate_hash_safe(hash: &str) -> Result<Option<String>> {
    config::DEFAULT_CONFIG.migrate_hash_safe(hash)

}

fn gen_salt(rng: &dyn SecureRandom) -> Vec<u8> {
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
    gen_salt(&SystemRandom::new())
}

#[cfg(test)]
mod api_tests {
    use super::*;
    use config::DEFAULT_PRIM;
    use hashing::{Algorithm, Output};
    use primitives::{Bcrypt, Hmac};

    #[test]
    fn sanity_check() {
        let password = "";
        let hash = hash_password(password);
        println!("Hash: {:?}", hash);

        // can't use password again
        let password = "";
        assert!(verify_password(&hash, password));
        assert!(!verify_password(&hash, "wrong password"));

        let password = "hunter2";
        let hash = hash_password(password);

        // can't use password again
        let password = "hunter2";
        assert!(verify_password(&hash, password));
        assert!(!verify_password(&hash, "wrong password"));
    }

    #[test]
    fn external_check() {
        let password = "hunter2";
        let hash = "$2a$10$u.Fhlm/a1DpHr/z5KrsLG.iZ7iM9r8DInJvZ57VArRKuhlHAoVZOi";
        let pwd_hash: Output = serde_mcf::from_str(hash).unwrap();
        println!("{:?}", pwd_hash);

        let expected_hash = pwd_hash.alg.hash_with_salt(password.as_bytes(), &pwd_hash.salt);
        assert_eq!(pwd_hash.hash, &expected_hash[..]);
        assert!(verify_password(&hash, password));
    }

    #[test]
    fn emoji_password() {
        let password = "emojisaregreat💖💖💖";
        let hash = hash_password(password);
        assert!(verify_password(&hash, password));
    }

    #[test]
    fn nested_hash() {
        let password = "hunter2";

        let fast_prim = Bcrypt::new(5);

        let params = Algorithm::Nested {
            inner: Box::new(Algorithm::Single(fast_prim.clone())),
            outer: fast_prim.clone(),
        };
        let hash = params.hash(&password);

        let password = "hunter2";
        println!("{:?}", hash);
        assert!(hash.verify(&password));

        let password = "hunter2";
        let hash = serde_mcf::to_string(&hash).unwrap();
        println!("{:?}", hash);
        let _hash: Output = serde_mcf::from_str(&hash).unwrap();
        println!("{:?}", _hash);
        assert!(verify_password(&hash, password));
    }

    #[test]
    fn verify_update() {
        let password = "hunter2";

        let params = Algorithm::Nested {
            inner: Box::new(Algorithm::default()),
            outer: DEFAULT_PRIM.clone(),
        };
        let hash = params.hash(&password);

        let password = "hunter2";
        assert!(hash.verify(&password));

        let password = "hunter2";
        let hash = serde_mcf::to_string(&hash).unwrap();
        assert!(verify_password(&hash, password));
    }

    #[test]
    fn migrate() {
        let password = "hunter2";

        let params = Algorithm::Single(Bcrypt::new(5));
        let mut hash = serde_mcf::to_string(&params.hash(&password)).unwrap();
        println!("Original: {:?}", hash);
        if let Some(new_hash) = migrate_hash(&hash) {
            hash = new_hash;
        }
        println!("Migrated: {:?}", hash);
        assert!(verify_password(&hash, password));

        if let HashUpdate::Verified(Some(new_hash)) = verify_password_update_hash(&hash, password) {
            let mut pwd_hash: Output = serde_mcf::from_str(&new_hash).unwrap();
            // Note, this is not the intended way to use these structs, but just
            // a sanity check to make sure the new algorithm is _actually_ the
            // supposed default.
            pwd_hash.alg = Algorithm::default();
            assert!(pwd_hash.verify(&password));
        } else {
            assert!(false, "hash was not verified/migrated");
        }
    }

    #[test]
    fn handles_broken_hashes() {
        // base hash: $$scrypt$ln=14,r=8,p=1$Yw/fI4D7b2PNqpUCg5UzKA$kp6humqf/GUV+6HQ/jND3gd8Zoz4VyBgGqk4DHt+k5c
        let password = "hunter2";

        // Missing param
        let hash = "$$scrypt$ln=14p=1$Yw/fI4D7b2PNqpUCg5UzKA$kp6humqf/GUV+6HQ/jND3gd8Zoz4VyBgGqk4DHt+k5c";
        assert!(!verify_password(&hash, password));

        // Incorrect hash-id
        let hash = "$$nocrypt$ln=14p=1$Yw/fI4D7b2PNqpUCg5UzKA$kp6humqf/GUV+6HQ/jND3gd8Zoz4VyBgGqk4DHt+k5c";
        assert!(!verify_password(&hash, password));

        // Missing salt
        let hash = "$$scrypt$ln=14p=1$$kp6humqf/GUV+6HQ/jND3gd8Zoz4VyBgGqk4DHt+k5c";
        assert!(!verify_password(&hash, password));

        // Incorrect number of fields
        let hash = "$$scrypt$ln=14p=1$kp6humqf/GUV+6HQ/jND3gd8Zoz4VyBgGqk4DHt+k5c";
        assert!(!verify_password(&hash, password));

        // Truncated hash
        let hash = "$$scrypt$ln=14,r=8,\
                    p=1$Yw/fI4D7b2PNqpUCg5UzKA$kp6humqf/GUV+6HQ/jND3gd8Zoz4VyBgGqk4DHt";
        assert!(!verify_password(&hash, password));

        // Extended hash
        let hash = "$$scrypt$ln=14,r=8,\
                    p=1$Yw/fI4D7b2PNqpUCg5UzKA$kp6humqf/GUV+6HQ/jND3gd8Zoz4VyBgGqk4DHt+k5cAAAA";
        assert!(!verify_password(&hash, password));
    }

    #[test]
    fn migrate_hash_ok() {
        let hash = "$2a$10$175ikf/E6E.73e83.fJRbODnYWBwmfS0ENdzUBZbedUNGO.99wJfa".to_owned();
        let new_hash = migrate_hash(&hash).unwrap();
        assert!(new_hash != hash);
        assert!(migrate_hash(&new_hash).is_none());
    }

    #[test]
    fn vpuh_ok() {
        let password = "hunter2";
        let cfg = Config::with_primitive(Bcrypt::default());
        let hash = cfg.hash_password(password);
        let res = verify_password_update_hash(&hash, "hunter2");
        let hash = match res {
            HashUpdate::Verified(Some(x)) => x,
            _ => panic!("should have migrated"),
        };
        assert_eq!(verify_password_update_hash(&hash, "hunter2"), HashUpdate::Verified(None));
        assert_eq!(verify_password_update_hash(&hash, "*******"), HashUpdate::Failed);
    }

    #[test]
    fn hash_and_key() {
        let password = "hunter2";

        let alg = Algorithm::Single(Bcrypt::default()).into_wrapped(Hmac::default().into());
        let hash = serde_mcf::to_string(&alg.hash(&password)).unwrap();
        assert!(verify_password(&hash, password));
    }
}
