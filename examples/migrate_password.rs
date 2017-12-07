extern crate libpasta;
use libpasta::rpassword::*;

#[derive(Debug)]
struct User {
    // ...
    password_hash: String,
}

fn migrate_users(users: &mut [User]) {
    // Step 1: Wrap old hash
    for user in users {
        libpasta::migrate_hash(&mut user.password_hash);
    }
}

fn auth_user(user: &mut User) {
    // Step 2: Update algorithm during log in
    let password = prompt_password_stdout("Enter password:").unwrap();
    if libpasta::verify_password_update_hash(&mut user.password_hash, &password) {
        println!("Password correct, new hash: \n{}", user.password_hash);
    } else {
        println!("Password incorrect, hash unchanged: \n{}",
                 user.password_hash);
    }
}

fn main() {
    let mut users = vec![User { password_hash: deprected_hash("hunter2") },
                         User { password_hash: deprected_hash("hunter3") },
                         User { password_hash: deprected_hash("letmein") },
                         User { password_hash: deprected_hash("password") }];

    migrate_users(&mut users);
    println!("Passwords migrated: {:?}", users);
    auth_user(&mut users[0]);
}

// Do not use this code as a good example of how to do hashing.
// This is intentionally awkward
use libpasta::{hashing, primitives};
extern crate serde_mcf;

fn deprected_hash(password: &str) -> String {
    let alg = hashing::Algorithm::Single(primitives::Bcrypt::default());
    serde_mcf::to_string(&alg.hash(password)).unwrap()
}
