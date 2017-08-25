extern crate libpasta;

#[macro_use]
mod common;

use libpasta::primitives::Pbkdf2;

config_test!(Pbkdf2);
