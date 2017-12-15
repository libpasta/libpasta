extern crate libc;
extern crate libpasta;
extern crate rpassword;

use libc::c_char;
use rpassword::prompt_password_stdout;

use std::ffi::{CStr, CString};

#[no_mangle]
pub extern fn read_password(prompt: *const c_char) -> *mut c_char {
    let prompt = unsafe {
        assert!(!prompt.is_null());
        CStr::from_ptr(prompt).to_str().unwrap()
    };
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
    let password = unsafe {
        assert!(!password.is_null());
        CStr::from_ptr(password).to_str().unwrap()
    };
    let output = libpasta::hash_password(password);
    CString::new(output).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn verify_password(hash: *const c_char, password: *const c_char) -> bool {
    let hash = unsafe {
        assert!(!hash.is_null());
        CStr::from_ptr(hash).to_str().unwrap()
    };
    let password = unsafe {
        assert!(!password.is_null());
        CStr::from_ptr(password).to_str().unwrap()
    };
    libpasta::verify_password(hash, password)
}

#[no_mangle]
pub extern "C" fn verify_password_update_hash(hash: *const c_char, password: *const c_char) -> *mut c_char {
    let mut new_hash = unsafe {
        assert!(!hash.is_null());
        CStr::from_ptr(hash).to_str().unwrap().to_owned()
    };
    let password = unsafe {
        assert!(!password.is_null());
        CStr::from_ptr(password).to_str().unwrap()
    };
    if libpasta::verify_password_update_hash(&mut new_hash, password) {
        CString::new(new_hash).unwrap().into_raw()
    } else {
        CString::new("").unwrap().into_raw()
    }
}

#[no_mangle]
pub extern "C" fn migrate_hash(hash: *const c_char) -> *mut c_char {
    let mut hash = unsafe {
        assert!(!hash.is_null());
        CStr::from_ptr(hash).to_str().unwrap().to_owned()
    };
    libpasta::migrate_hash(&mut hash);
    CString::new(hash).unwrap().into_raw()
}



