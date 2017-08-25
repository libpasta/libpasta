extern crate libpasta;
use libpasta::rpassword::*;

struct User {
    // ...
    password_hash: String,
}

fn auth_user(user: &User) {
    let password = prompt_password_stdout("Enter password:").unwrap();
    if libpasta::verify_password(&user.password_hash, password) {
        println!("The password is correct!");
        // ~> Handle correct password
    } else {
        println!("Incorrect password.");
        // ~> Handle incorrect password
    }
}


fn main() {
    let user = User { password_hash: libpasta::hash_password("hunter2".to_owned()) };
    auth_user(&user);
}
