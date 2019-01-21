extern crate libc;
extern crate libpasta;
extern crate rpassword;

use libpasta::HashUpdate;
use libpasta::primitives::*;
use libpasta::config::Config;

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

macro_rules! box_ptr {
    ($x:expr) => (
        Box::into_raw(Box::new($x))
    )
}

#[repr(C)]
pub enum HashUpdateFfi {
    Updated(*mut c_char),
    Ok,
    Failed,
}

impl From<HashUpdate> for HashUpdateFfi {
    fn from(other: HashUpdate) -> Self {
        match other {
            HashUpdate::Verified(Some(x)) => HashUpdateFfi::Updated(CString::new(x).unwrap().into_raw()),
            HashUpdate::Verified(None) => HashUpdateFfi::Ok,
            HashUpdate::Failed => HashUpdateFfi::Failed,
        }
    }
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
pub extern "C" fn config_new() -> *mut Config {
    box_ptr!(Config::default())
}

#[no_mangle]
pub extern "C" fn config_free(config: *mut Config) {
    let _config   = unsafe { ffi_ref!(config) };
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
pub extern "C" fn verify_password_update_hash(hash: *const c_char, password: *const c_char) -> *mut HashUpdateFfi {
    let hash     = unsafe { ffi_string!(hash) };
    let password = unsafe { ffi_string!(password) };
    box_ptr!(libpasta::verify_password_update_hash(hash, password).into())
}

#[no_mangle]
pub extern "C" fn config_verify_password_update_hash(config: *const Config, hash: *const c_char, password: *const c_char) -> *mut HashUpdateFfi {
    let config   = unsafe { ffi_ref!(config) };
    let hash     = unsafe { ffi_string!(hash) };
    let password = unsafe { ffi_string!(password) };
    box_ptr!(config.verify_password_update_hash(hash, password).into())
}

#[no_mangle]
pub extern "C" fn migrate_hash(hash: *const c_char) -> *mut HashUpdateFfi {
    let hash = unsafe { ffi_string!(hash).to_owned() };
    if let Some(new_hash) = libpasta::migrate_hash(&hash) {
        box_ptr!(HashUpdateFfi::Updated(CString::new(new_hash).unwrap().into_raw()))
    } else {
        box_ptr!(HashUpdateFfi::Ok)
    }
}

#[no_mangle]
pub extern "C" fn config_migrate_hash(config: *const Config, hash: *const c_char) -> *mut HashUpdateFfi {
    let config = unsafe { ffi_ref!(config) };
    let hash = unsafe { ffi_string!(hash).to_owned() };
    if let Some(new_hash) = config.migrate_hash(&hash) {
        box_ptr!(HashUpdateFfi::Updated(CString::new(new_hash).unwrap().into_raw()))
    } else {
        box_ptr!(HashUpdateFfi::Ok)
    }
}


#[no_mangle]
pub extern "C" fn config_with_primitive(prim: *const Primitive) -> *mut Config {
    let prim = unsafe { ffi_ref!(prim) };
    box_ptr!(Config::with_primitive(prim.clone()))
}

#[no_mangle]
pub extern "C" fn default_argon2i() -> *mut Primitive {
    box_ptr!(Argon2::default())
}

#[no_mangle]
pub extern "C" fn default_bcrypt() -> *mut Primitive {
    box_ptr!(Bcrypt::default())
}

#[no_mangle]
pub extern "C" fn default_pbkdf2i() -> *mut Primitive {
    box_ptr!(Pbkdf2::default())
}

#[no_mangle]
pub extern "C" fn default_scrypt() -> *mut Primitive {
    box_ptr!(Scrypt::default())
}

#[no_mangle]
pub extern "C" fn new_argon2i(passes: c_uint, lanes: c_uint, kib: c_uint) -> *mut Primitive {
    box_ptr!(Argon2::new(passes, lanes, kib))
}

#[no_mangle]
pub extern "C" fn new_bcrypt(cost: c_uint) -> *mut Primitive {
    box_ptr!(Bcrypt::new(cost))
}

#[no_mangle]
pub extern "C" fn new_scrypt(log_n: c_uchar, r: c_uint, p: c_uint) -> *mut Primitive {
    box_ptr!(Scrypt::new(log_n, r, p))
}

#[no_mangle]
pub extern "C" fn free_Primitive(prim: *mut Primitive) {
    let _prim = unsafe { ffi_ref!(prim) };
}


#[cfg(test)]
mod test {
    use std::ffi::CString;

    #[test]
    fn test_migrate() {
        unsafe {
            let hash = "$2a$10$vI8aWBnW3fID.ZQ4/zo1G.q1lRps.9cGLcZEiGDMVr5yUP1KUOYTa";
            let hash = CString::new(hash).unwrap().into_raw();
            let password = "my password";
            let password = CString::new(password).unwrap().into_raw();
            let res = super::verify_password_update_hash(hash, password);
        }

    }
}