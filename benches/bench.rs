#![feature(test)]

extern crate argon2rs;
extern crate cargon;
extern crate libpasta;
extern crate serde_mcf;
extern crate test;
extern crate time;
use test::Bencher;


use libpasta::primitives::{Argon2, Scrypt, Primitive};
use libpasta::hashing::Algorithm;

#[bench]
fn empty(b: &mut Bencher) {
    b.iter(|| 1)
}

use std::fs::File;

#[bench]
fn raw_argon2(_b: &mut Bencher) {
    let _f1 = File::create("native.txt").unwrap();
    let _f2 = File::create("ffi.txt").unwrap();
    let reps = 10;
    let password = [0; 16];
    let salt = [1; 16];
    let t_cost = 3;
    let thread_test = [1, 2, 4, 8];
    let mut out = [0u8; 32];
    let mut m_cost = 1 << 10;
    while m_cost <= 1 << 22 {
        for threads in &thread_test {
            let alg = argon2rs::Argon2::new(t_cost, *threads, m_cost, argon2rs::Variant::Argon2i)
                .unwrap();
            let mut alg_ffi = mk_cargon(&alg, &mut out, &password, &salt, &[], &[]);
            let prim: Primitive = Argon2::new(t_cost, *threads, m_cost);
            let pastalg = Algorithm::Single(prim);

            let start = time::precise_time_ns();
            for _ in 0..reps {
                alg.hash(&mut out, &password, &salt, &[], &[]);
            }
            let end = time::precise_time_ns();
            let native = (end - start) as f64;

            let start = time::precise_time_ns();
            for _ in 0..reps {
                unsafe {
                    cargon::argon2_ctx(&mut alg_ffi, argon2rs::Variant::Argon2i as usize);
                }
            }
            let end = time::precise_time_ns();
            let ffi = (end - start) as f64;

            let start = time::precise_time_ns();
            for _ in 0..reps {
                let _ = serde_mcf::to_string(&pastalg.hash("hunter2"));
            }
            let end = time::precise_time_ns();
            let libp = (end - start) as f64;

            println!("{} {} iterations  {} MiB {} threads ... {} reps",
                     "Argon2i",
                     t_cost,
                     m_cost / 1024,
                     threads,
                     reps);
            println!("Native:   {:.4} seconds", native / 1_000_000_000f64);
            println!("libpasta: {:.4} seconds", libp / 1_000_000_000f64);
            println!("FFI:      {:.4} seconds\n", ffi / 1_000_000_000f64);
        }
        m_cost <<= 1;

    }
}


#[bench]
fn pasta_hash_static(b: &mut Bencher) {
    let password = "hunter2";
    b.iter(|| libpasta::hash_password(password))
}

#[bench]
fn pasta_hash_dyn(b: &mut Bencher) {
    let password = "hunter2";
    let alg = Algorithm::Single(Scrypt::new(14, 8, 1));
    b.iter(|| {
        alg.hash(password)
    })
}

use std::ptr;
fn mk_cargon(a2: &argon2rs::Argon2,
             out: &mut [u8],
             p: &[u8],
             s: &[u8],
             k: &[u8],
             x: &[u8])
             -> cargon::CargonContext {
    let (_, kib, passes, lanes) = a2.params();
    cargon::CargonContext {
        out: out.as_mut_ptr(),
        outlen: out.len() as u32,
        pwd: p.as_ptr(),
        pwdlen: p.len() as u32,
        salt: s.as_ptr(),
        saltlen: s.len() as u32,
        secret: k.as_ptr(),
        secretlen: k.len() as u32,
        ad: x.as_ptr(),
        adlen: x.len() as u32,

        t_cost: passes,
        m_cost: kib,
        lanes: lanes,
        threads: lanes,
        version: 0x13,
        allocate_fptr: ptr::null(),
        deallocate_fptr: ptr::null(),
        flags: cargon::ARGON2_FLAG_CLEAR_MEMORY,
    }
}
