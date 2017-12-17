extern crate libc;
extern crate libpasta;
extern crate rpassword;

use libc::{c_char, c_uchar, c_uint};
use rpassword::prompt_password_stdout;

use std::ffi::{CStr, CString};

macro_rules! ffi_ref {
    ($name:ident) => (
        {
            assert!(!$name.is_null());
            &*$name
        }
    );
}

macro_rules! ffi_string {
    ($name:ident) => (
        {
            assert!(!$name.is_null());
            CStr::from_ptr($name).to_str().unwrap()
        }
    )
}

#[no_mangle]
pub extern fn read_password(prompt: *const c_char) -> *mut c_char {
    let prompt = unsafe { ffi_string!(prompt) };
    let password = prompt_password_stdout(prompt).unwrap();
    CString::new(password).unwrap().into_raw()
}

// Required to free memory properly
#[no_mangle]
pub extern fn free_string(s: *mut c_char) {
    unsafe {
        if s.is_null() { return }
        CString::from_raw(s)
    };
}

#[no_mangle]
pub extern fn hash_password(password: *const c_char) -> *mut c_char {
    let password = unsafe { ffi_string!(password) };
    let output = libpasta::hash_password(password);
    CString::new(output).unwrap().into_raw()
}


#[no_mangle]
pub extern "C" fn config_hash_password(config: *const Config, password: *const c_char) -> *mut c_char {
    let config = unsafe { ffi_ref!(config) };
    let password = unsafe { ffi_string!(password) };
    let output = config.hash_password(password);
    CString::new(output).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn verify_password(hash: *const c_char, password: *const c_char) -> bool {
    let hash = unsafe { ffi_string!(hash) };
    let password = unsafe { ffi_string!(password) };

    libpasta::verify_password(hash, password)
}

#[no_mangle]
pub extern "C" fn config_verify_password(config: *const Config, hash: *const c_char, password: *const c_char) -> bool {
    let config = unsafe { ffi_ref!(config) };
    let hash = unsafe { ffi_string!(hash) };
    let password = unsafe { ffi_string!(password) };
    config.verify_password(hash, password)
}

#[no_mangle]
pub extern "C" fn verify_password_update_hash(hash: *const c_char, password: *const c_char, new_hash: *mut *mut c_char) -> bool {
    let mut hash = unsafe { ffi_string!(hash).to_owned() };
    let password = unsafe { ffi_string!(password) };
    let res = libpasta::verify_password_update_hash(&mut hash, password);
    unsafe {
        *new_hash = CString::new(hash).unwrap().into_raw();
    }
    res
}

#[no_mangle]
pub extern "C" fn config_verify_password_update_hash(config: *const Config, hash: *const c_char, password: *const c_char, new_hash: *mut *mut c_char) -> bool {
    let config = unsafe { ffi_ref!(config) };
    let mut hash = unsafe { ffi_string!(hash).to_owned() };
    let password = unsafe { ffi_string!(password) };
    let res = config.verify_password_update_hash(&mut hash, password);
    unsafe {
        *new_hash = CString::new(hash).unwrap().into_raw();
    }
    res
}

// use libpasta::primitives::Primitive;
use libpasta::primitives::*;
use libpasta::config::Config;

#[no_mangle]
pub extern "C" fn migrate_hash(hash: *const c_char) -> *mut c_char {
    let mut hash = unsafe { ffi_string!(hash).to_owned() };
    libpasta::migrate_hash(&mut hash);
    CString::new(hash).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn config_migrate_hash(config: *const Config, hash: *const c_char) -> *mut c_char {
    let config = unsafe { ffi_ref!(config) };
    let mut hash = unsafe { ffi_string!(hash).to_owned() };
    config.migrate_hash(&mut hash);
    CString::new(hash).unwrap().into_raw()
}


#[no_mangle]
pub extern "C" fn config_with_primitive(prim: *const Primitive) -> *mut Config {
    let prim = unsafe { ffi_ref!(prim) };
    Box::into_raw(Box::new(Config::with_primitive(prim.clone())))
}

#[no_mangle]
pub extern "C" fn default_argon2i() -> *mut Primitive {
    Box::into_raw(Box::new(Argon2::default()))
}

#[no_mangle]
pub extern "C" fn default_bcrypt() -> *mut Primitive {
    Box::into_raw(Box::new(Bcrypt::default()))
}

#[no_mangle]
pub extern "C" fn default_pbkdf2i() -> *mut Primitive {
    Box::into_raw(Box::new(Pbkdf2::default()))
}

#[no_mangle]
pub extern "C" fn default_scrypt() -> *mut Primitive {
    Box::into_raw(Box::new(Scrypt::default()))
}

#[no_mangle]
pub extern "C" fn new_argon2i(passes: c_uint, lanes: c_uint, kib: c_uint) -> *mut Primitive {
    Box::into_raw(Box::new(Argon2::new(passes, lanes, kib)))
}

#[no_mangle]
pub extern "C" fn new_bcrypt(cost: c_uint) -> *mut Primitive {
    Box::into_raw(Box::new(Bcrypt::new(cost)))
}

#[no_mangle]
pub extern "C" fn new_scrypt(log_n: c_uchar, r: c_uint, p: c_uint) -> *mut Primitive {
    Box::into_raw(Box::new(Scrypt::new(log_n, r, p)))
}

#[no_mangle]
pub extern "C" fn free_Primitive(prim: *mut Primitive) {
    let _prim = unsafe { ffi_ref!(prim) };
}

#[no_mangle]
pub extern "C" fn free_Config(config: *mut Config) {
    let _config = unsafe { ffi_ref!(config) };

}

