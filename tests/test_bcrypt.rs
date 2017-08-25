extern crate libpasta;

#[macro_use]
mod common;

use libpasta::primitives::Bcrypt;

config_test!(Bcrypt);
