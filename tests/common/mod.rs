#![allow(dead_code, unused_macros)]

extern crate env_logger;

use std::path::PathBuf;

macro_rules! config_test {
    ($name:ident) => (
        #[macro_use]
        extern crate log;

        #[test]
        fn test_prim() {
            common::init_test();

            let password = "hunter2";
            libpasta::config::set_primitive($name::default());
            trace!("config setup as: {}", libpasta::config::to_string());
            let password_hash = libpasta::hash_password(password.to_string());
            assert!(libpasta::verify_password(&password_hash, password.to_string()));
        }
    
    )
}

pub fn get_test_path(filename: &str) -> PathBuf {
    let mut path = PathBuf::from(file!());
    path.pop();
    path.pop();
    path.push(filename);
    path
}

pub fn init_test() {
    self::env_logger::init().unwrap();
}