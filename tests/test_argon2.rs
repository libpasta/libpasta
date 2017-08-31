extern crate libpasta;

#[macro_use]
mod common;

use libpasta::primitives::Argon2;

config_test!(Argon2, "$$argon2");
