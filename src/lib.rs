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
//! For a more comprehensive introduction, see: https://libpasta.github.io/
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
    new_ret_no_self, // we use fn new() -> Primitive for convenience
    use_self, // currently broken in  clippy v0.0.153
)]
#![deny(
    const_err,
    dead_code,
    deprecated,
    exceeding_bitshifts,
    fat_ptr_transmutes,
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

extern crate data_encoding;
#[macro_use]
extern crate error_chain;
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
    // Create the Error, ErrorKind, ResultExt, and Result types
    error_chain!{
        foreign_links {
            Deserialize(serde_mcf::de::Error) #[doc = "Errors from deserializing MCF password hashes."] ;
            Ring(ring::error::Unspecified) #[doc = "Errors originiating from `ring`"] ;
            Serialize(serde_mcf::ser::Error) #[doc = "Errors from serializing to a MCF password hash."] ;
        }
    }
}

use errors::*;

use ring::rand::{SecureRandom, SystemRandom};

#[macro_use]
mod bench;

pub mod config;
pub mod key;
pub mod hashing;
use hashing::Output;

pub mod primitives;


/// A simple wrapper for a password to denote it is a cleartext password.
pub struct Cleartext(Vec<u8>);

impl From<String> for Cleartext {
    fn from(thing: String) -> Self {
        Cleartext(thing.into_bytes())
    }
}

/// Generates a default hash for a given password.
///
/// This is the simplest way to use libpasta, and uses sane defaults.
/// ## Panics
/// If there is any error while attempting to hash, will panic.
/// For default usage this should not happen.
pub fn hash_password(password: String) -> String {
    hash_password_safe(password).expect("failed to hash password")
}

/// Same as `hash_password` but returns `Result` to allow error handling.
/// TODO: decide on which API is best to use.
#[doc(hidden)]
pub fn hash_password_safe(password: String) -> Result<String> {
    let pwd_hash = config::DEFAULT_ALG.hash(password.into())?;
    Ok(serde_mcf::to_string(&pwd_hash)?)
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
    Ok(pwd_hash.verify(password.into()))
}

/// Verifies a supplied password against a previously computed password hash,
/// and performs an in-place update of the hash value if the password verifies.
/// Hence this needs to take a mutable `String` reference.
pub fn verify_password_update_hash(hash: &mut String, password: String) -> bool {
    verify_password_update_hash_safe(hash, password).unwrap_or(false)
}

/// Same as `verify_password_update_hash`, but returns `Result` to allow error handling.
#[doc(hidden)]
pub fn verify_password_update_hash_safe(hash: &mut String, password: String) -> Result<bool> {
    let pwd_hash: Output = serde_mcf::from_str(hash)?;
    if pwd_hash.verify(password.clone().into()) {
        if pwd_hash.alg != *config::DEFAULT_ALG {
            let new_hash = serde_mcf::to_string(&config::DEFAULT_ALG.hash(password.into())?)?;
            *hash = new_hash;
        }
        Ok(true)
    } else {
        Ok(false)
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
pub fn migrate_hash(hash: &mut String) {
    migrate_hash_safe(hash).expect("failed to migrate password");
}

/// Same as `migrate_hash` but returns `Result` to allow error handling.
#[doc(hidden)]
pub fn migrate_hash_safe(hash: &mut String) -> Result<()> {
    use hashing::Algorithm;
    let pwd_hash: Output = serde_mcf::from_str(hash)?;

    if pwd_hash.alg == *config::DEFAULT_ALG {
        // no need to migrate
        return Ok(());
    }
    // This is wrong, needs to be `def` as `outer`.
    let new_params = Algorithm::Nested { outer: config::DEFAULT_PRIM.clone(), inner: Box::new(pwd_hash.alg) };

    let new_salt = pwd_hash.salt;

    let new_hash = config::DEFAULT_ALG.hash_with_salt(&pwd_hash.hash, &new_salt);
    let new_hash = Output {
        alg: new_params,
        hash: new_hash,
        salt: new_salt,
    };

    *hash = serde_mcf::to_string(&new_hash)?;
    Ok(())
}

fn gen_salt() -> Result<Vec<u8>> {
    let mut salt = vec![0_u8; 16];
    let rng = SystemRandom;
    rng.fill(&mut salt)?;
    Ok(salt)
}

#[cfg(test)]
fn get_salt() -> Vec<u8> {
    gen_salt().unwrap()
}

#[cfg(test)]
mod api_tests {
    use super::*;
    use config::DEFAULT_PRIM;
    use hashing::{Algorithm, Output};
    use primitives::{Bcrypt, Hmac};

    #[test]
    fn sanity_check() {
        let password = "".to_owned();
        let hash = hash_password(password);
        println!("Hash: {:?}", hash);

        // can't use password again
        let password = "".to_owned();
        assert!(verify_password(&hash, password));
        assert!(!verify_password(&hash,"wrong password".to_owned()));

        let password = "hunter2".to_owned();
        let hash = hash_password(password);

        // can't use password again
        let password = "hunter2".to_owned();
        assert!(verify_password(&hash, password));
        assert!(!verify_password(&hash,"wrong password".to_owned()));
    }

    #[test]
    fn external_check() {
        let password = "hunter2".to_owned();
        let hash = "$2a$10$u.Fhlm/a1DpHr/z5KrsLG.iZ7iM9r8DInJvZ57VArRKuhlHAoVZOi";
        let pwd_hash: Output = serde_mcf::from_str(hash).unwrap();
        println!("{:?}", pwd_hash);

        let expected_hash = pwd_hash.alg.hash_with_salt(password.as_bytes(), &pwd_hash.salt, );
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

        let params = Algorithm::Nested { inner: Box::new(Algorithm::default()), outer: DEFAULT_PRIM.clone() };
        let hash = params.hash(password.into()).unwrap();

        let password = "hunter2".to_owned();
        println!("{:?}", hash);
        assert!(hash.verify(password.into()));

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

        let params = Algorithm::Nested { inner: Box::new(Algorithm::default()), outer: DEFAULT_PRIM.clone() };
        let hash = params.hash(password.into()).unwrap();

        let password = "hunter2".to_owned();
        assert!(hash.verify(password.into()));

        let password = "hunter2".to_owned();
        let hash = serde_mcf::to_string(&hash).unwrap();
        assert!(verify_password(&hash, password));
    }

    #[test]
    fn migrate() {
        let password = "hunter2".to_owned();

        let params = Algorithm::Single(Bcrypt::default());
        let mut hash = serde_mcf::to_string(&params.hash(password.into()).unwrap()).unwrap();
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
        assert!(pwd_hash.verify(password.into()));
    }

    #[test]
    fn handles_broken_hashes() {
        // base hash: $$scrypt-mcf$log_n=14,r=8,p=1$Yw/fI4D7b2PNqpUCg5UzKA$kp6humqf/GUV+6HQ/jND3gd8Zoz4VyBgGqk4DHt+k5c
        let password = "hunter2".to_owned();

        // Missing param
        let hash = "$$scrypt-mcf$log_n=14p=1$Yw/fI4D7b2PNqpUCg5UzKA$kp6humqf/GUV+6HQ/jND3gd8Zoz4VyBgGqk4DHt+k5c";
        assert!(!verify_password(&hash, password.clone()));

        // Incorrect hash-id
        let hash = "$$nocrypt-mcf$log_n=14p=1$Yw/fI4D7b2PNqpUCg5UzKA$kp6humqf/GUV+6HQ/jND3gd8Zoz4VyBgGqk4DHt+k5c";
        assert!(!verify_password(&hash, password.clone()));

        // Missing salt
        let hash = "$$scrypt-mcf$log_n=14p=1$$kp6humqf/GUV+6HQ/jND3gd8Zoz4VyBgGqk4DHt+k5c";
        assert!(!verify_password(&hash, password.clone()));

        // Incorrect number of fields
        let hash = "$$scrypt-mcf$log_n=14p=1$kp6humqf/GUV+6HQ/jND3gd8Zoz4VyBgGqk4DHt+k5c";
        assert!(!verify_password(&hash, password.clone()));

        // Truncated hash
        let hash = "$$scrypt-mcf$log_n=14,r=8,p=1$Yw/fI4D7b2PNqpUCg5UzKA$kp6humqf/GUV+6HQ/jND3gd8Zoz4VyBgGqk4DHt";
        assert!(!verify_password(&hash, password.clone()));

        // Extended hash
        let hash = "$$scrypt-mcf$log_n=14,r=8,p=1$Yw/fI4D7b2PNqpUCg5UzKA$kp6humqf/GUV+6HQ/jND3gd8Zoz4VyBgGqk4DHt+k5cAAAA";
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
        let hash = serde_mcf::to_string(&alg.hash(password.clone().into()).unwrap()).unwrap();
        assert!(verify_password(&hash, password));
    }
}
