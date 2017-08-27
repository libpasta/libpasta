extern crate libpasta;

#[macro_use]
mod common;

use libpasta::primitives::Scrypt;

config_test!(Scrypt, "$$scrypt");
