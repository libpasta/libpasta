extern crate libpasta;

use libpasta::primitives::Bcrypt;

fn main() {
    libpasta::config::set_primitive(Bcrypt::new(15));
    let password_hash = libpasta::hash_password("hunter2".to_string());
    println!("The hashed password is: '{}'", password_hash);
    // Prints bcrypt hash
}
