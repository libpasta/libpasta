extern crate libpasta;

// We re-export the rpassword crate for CLI password input.
use libpasta::rpassword::*;

fn main() {
    let password = prompt_password_stdout("Please enter your password:").unwrap();
    let password_hash = libpasta::hash_password(password);
    println!("The hashed password is: '{}'", password_hash);
}
