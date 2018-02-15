extern crate libpasta;
use libpasta::rpassword::*;
use libpasta::HashUpdate;

#[derive(Debug)]
struct User {
    // ...
    password_hash: String,
}

fn migrate_users(users: &mut [User]) {
    // Step 1: Wrap old hash
    for user in users {
        if let Some(new_hash) = libpasta::migrate_hash(&user.password_hash) {
            user.password_hash = new_hash;
        }
    }
}

fn auth_user(user: &mut User) {
    // Step 2: Update algorithm during log in
    let password = prompt_password_stdout("Enter password:").unwrap();

    match libpasta::verify_password_update_hash(&user.password_hash, &password) {
        HashUpdate::Verified(output) => {
            if let Some(new_hash) = output {
                user.password_hash = new_hash;
            }
            println!("Password correct, new hash: \n{}", user.password_hash);
        },
        HashUpdate::Failed => {
            println!("Password incorrect, hash unchanged: \n{}",
                     user.password_hash);
        }
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

use libpasta::{config, primitives};

fn deprected_hash(password: &str) -> String {
    let config = config::Config::with_primitive(primitives::Bcrypt::default());
    config.hash_password(password)
}
