#![cfg(feature = "benchmarking")]

use criterion::{criterion_group, criterion_main, Criterion};
use pqc_kyber::*;
use rand::{rngs::StdRng, SeedableRng};

fn build_keypair() -> ([u8; KYBER_PUBLICKEYBYTES], [u8; KYBER_SECRETKEYBYTES]) {
    let mut rng = StdRng::seed_from_u64(0xA11CE);
    let mut pk = [0u8; KYBER_PUBLICKEYBYTES];
    let mut sk = [0u8; KYBER_SECRETKEYBYTES];
    let seed = [0x11u8; KYBER_SYMBYTES];
    let z = [0x22u8; KYBER_SYMBYTES];
    let bufs = Some((seed.as_slice(), z.as_slice()));
    crypto_kem_keypair(&mut pk, &mut sk, &mut rng, bufs).unwrap();
    (pk, sk)
}

fn build_ciphertext(pk: &[u8]) -> [u8; KYBER_CIPHERTEXTBYTES] {
    let mut rng = StdRng::seed_from_u64(0xB0B);
    let mut ct = [0u8; KYBER_CIPHERTEXTBYTES];
    let mut ss = [0u8; KYBER_SSBYTES];
    let encap_seed = [0x33u8; KYBER_SYMBYTES];
    crypto_kem_enc(&mut ct, &mut ss, pk, &mut rng, Some(encap_seed.as_slice())).unwrap();
    ct
}

fn keypair(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0xC0DE);
    let mut pk = [0u8; KYBER_PUBLICKEYBYTES];
    let mut sk = [0u8; KYBER_SECRETKEYBYTES];
    let seed = [0x44u8; KYBER_SYMBYTES];
    let z = [0x55u8; KYBER_SYMBYTES];
    let bufs = Some((seed.as_slice(), z.as_slice()));

    c.bench_function("Keypair Generation", |b| {
        b.iter(|| {
            crypto_kem_keypair(&mut pk, &mut sk, &mut rng, bufs).unwrap();
        })
    });
}

fn encap(c: &mut Criterion) {
    let (pk, _) = build_keypair();
    let mut rng = StdRng::seed_from_u64(0xD00D);
    let mut ct = [0u8; KYBER_CIPHERTEXTBYTES];
    let mut ss = [0u8; KYBER_SSBYTES];
    let encap_seed = [0x66u8; KYBER_SYMBYTES];

    c.bench_function("Encapsulate", |b| {
        b.iter(|| {
            crypto_kem_enc(&mut ct, &mut ss, &pk, &mut rng, Some(encap_seed.as_slice())).unwrap();
        })
    });
}

fn decap(c: &mut Criterion) {
    let (pk, sk) = build_keypair();
    let ct = build_ciphertext(&pk);

    c.bench_function("Decapsulate", |b| {
        b.iter(|| {
            let _ = decapsulate(&ct, &sk);
        })
    });
}

fn decap_fail(c: &mut Criterion) {
    let (pk, sk) = build_keypair();
    let mut bad_ct = build_ciphertext(&pk);
    bad_ct[0] ^= 0x80;

    c.bench_function("Decapsulate Failure", |b| {
        b.iter(|| {
            let _ = decapsulate(&bad_ct, &sk);
        })
    });
}

criterion_group!(benches, keypair, encap, decap, decap_fail);
criterion_main!(benches);
