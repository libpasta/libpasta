extern crate argon2rs;
extern crate cargon;
extern crate criterion;
extern crate libpasta;
extern crate serde_mcf;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use libpasta::hashing::Algorithm;
use libpasta::primitives::{Argon2, Primitive, Scrypt};

fn argon2_comparison(c: &mut Criterion) {
    let password = [0; 16];
    let salt = [1; 16];
    let t_cost = 3;
    let thread_test = [1, 4];
    let mut out = [0u8; 32];
    let m_costs: Vec<u32> = (10..=14).map(|i| 1 << i).collect();

    let mut group = c.benchmark_group("argon2");

    for &m_cost in &m_costs {
        group.throughput(Throughput::Bytes(u64::from(m_cost)));
        for threads in &thread_test {
            let alg = argon2rs::Argon2::new(t_cost, *threads, m_cost, argon2rs::Variant::Argon2i)
                .unwrap();
            group.bench_function(
                BenchmarkId::from_parameter(format!("native_{}", threads)),
                |b| b.iter(|| alg.hash(&mut out, &password, &salt, &[], &[])),
            );
        }
    }

    for &m_cost in &m_costs {
        group.throughput(Throughput::Bytes(u64::from(m_cost)));
        for threads in &thread_test {
            let alg = argon2rs::Argon2::new(t_cost, *threads, m_cost, argon2rs::Variant::Argon2i)
                .unwrap();
            let mut alg_ffi = mk_cargon(&alg, &mut out, &password, &salt, &[], &[]);
            group.bench_function(
                BenchmarkId::from_parameter(format!("ffi_{}", threads)),
                |b| {
                    b.iter(|| unsafe {
                        cargon::argon2_ctx(&mut alg_ffi, argon2rs::Variant::Argon2i as usize);
                    })
                },
            );
        }
    }

    for &m_cost in &m_costs {
        group.throughput(Throughput::Bytes(u64::from(m_cost)));
        for threads in &thread_test {
            let prim: Primitive = Argon2::new(t_cost, *threads, m_cost);
            let pastalg = Algorithm::Single(prim);
            group.bench_function(
                BenchmarkId::from_parameter(format!("pasta_{}", threads)),
                |b| b.iter(|| pastalg.hash_with_salt(&password, &salt)),
            );
        }
    }
}

fn pasta_hash_static(c: &mut Criterion) {
    let password = "hunter2";
    c.bench_function("pasta_hash", |b| {
        b.iter(|| libpasta::hash_password(password))
    });
}

fn pasta_hash_dyn(c: &mut Criterion) {
    let password = "hunter2";
    let alg = Algorithm::Single(Scrypt::new(14, 8, 1));
    c.bench_function("pasta_hash_dyn_alg", |b| b.iter(|| alg.hash(password)));
}

use std::ptr;
fn mk_cargon(
    a2: &argon2rs::Argon2,
    out: &mut [u8],
    p: &[u8],
    s: &[u8],
    k: &[u8],
    x: &[u8],
) -> cargon::CargonContext {
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
        lanes,
        threads: lanes,
        version: 0x13,
        allocate_fptr: ptr::null(),
        deallocate_fptr: ptr::null(),
        flags: cargon::ARGON2_FLAG_CLEAR_MEMORY,
    }
}

criterion_group!(
    benches,
    pasta_hash_static,
    pasta_hash_dyn,
    argon2_comparison
);
criterion_main!(benches);
