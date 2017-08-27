extern crate libpasta;

#[macro_use]
mod common;

use libpasta::primitives::RingPbkdf2;

config_test!(RingPbkdf2, "$$pbkdf2");
