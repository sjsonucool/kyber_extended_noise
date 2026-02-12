#![allow(clippy::precedence)]
use crate::{params::*, poly::*};

#[derive(Clone)]
pub struct Polyvec {
    pub vec: [Poly; KYBER_K],
}

impl Copy for Polyvec {}

impl Polyvec {
    pub fn new() -> Self {
        Polyvec {
            vec: [Poly::new(); KYBER_K],
        }
    }
}

/// Name:  polyvec_compress
///
/// Description: Compress and serialize vector of polynomials
///
/// Arguments:   - [u8] r: output byte array (needs space for KYBER_POLYVECCOMPRESSEDBYTES)
///  - const Polyvec a: input vector of polynomials
pub fn polyvec_compress(r: &mut [u8], a: Polyvec) {
    for i in 0..KYBER_K {
        poly_tobytes(&mut r[i * KYBER_POLYBYTES..(i + 1) * KYBER_POLYBYTES], a.vec[i]);
    }
}

/// Name:  polyvec_decompress
///
/// Description: De-serialize and decompress vector of polynomials;
///  approximate inverse of polyvec_compress
///
/// Arguments:   - Polyvec r:   output vector of polynomials
///  - [u8] a: input byte array (of length KYBER_POLYVECCOMPRESSEDBYTES)
pub fn polyvec_decompress(r: &mut Polyvec, a: &[u8]) {
    for i in 0..KYBER_K {
        poly_frombytes(
            &mut r.vec[i],
            &a[i * KYBER_POLYBYTES..(i + 1) * KYBER_POLYBYTES],
        );
    }
}

/// Name:  polyvec_tobytes
///
/// Description: Serialize vector of polynomials
///
/// Arguments:   - [u8] r: output byte array (needs space for KYBER_POLYVECBYTES)
///  - const Polyvec a: input vector of polynomials
pub fn polyvec_tobytes(r: &mut [u8], a: &Polyvec) {
    for i in 0..KYBER_K {
        poly_tobytes(&mut r[i * KYBER_POLYBYTES..], a.vec[i]);
    }
}

/// Name:  polyvec_frombytes
///
/// Description: De-serialize vector of polynomials;
///  inverse of polyvec_tobytes
///
/// Arguments:   - [u8] r: output byte array
///  - const Polyvec a: input vector of polynomials (of length KYBER_POLYVECBYTES)
pub fn polyvec_frombytes(r: &mut Polyvec, a: &[u8]) {
    for i in 0..KYBER_K {
        poly_frombytes(&mut r.vec[i], &a[i * KYBER_POLYBYTES..]);
    }
}

/// Name:  polyvec_ntt
///
/// Description: Apply forward NTT to all elements of a vector of polynomials
///
/// Arguments:   - Polyvec r: in/output vector of polynomials
pub fn polyvec_ntt(r: &mut Polyvec) {
    for i in 0..KYBER_K {
        poly_ntt(&mut r.vec[i]);
    }
}

/// Name:  polyvec_invntt
///
/// Description: Apply inverse NTT to all elements of a vector of polynomials
///
/// Arguments:   - Polyvec r: in/output vector of polynomials
pub fn polyvec_invntt_tomont(r: &mut Polyvec) {
    for i in 0..KYBER_K {
        poly_invntt_tomont(&mut r.vec[i]);
    }
}

/// Name:  polyvec_basemul_acc_montgomery
///
/// Description: Pointwise multiply elements of a and b and accumulate into r
///
/// Arguments: - poly *r:  output polynomial
///  - const Polyvec a: first input vector of polynomials
///  - const Polyvec b: second input vector of polynomials
pub fn polyvec_basemul_acc_montgomery(r: &mut Poly, a: &Polyvec, b: &Polyvec) {
    let mut t = Poly::new();
    // Schoolbook negacyclic accumulate: r = sum a_i * b_i
    poly_mul_negacyclic(r, &a.vec[0], &b.vec[0]);
    for i in 1..KYBER_K {
        poly_mul_negacyclic(&mut t, &a.vec[i], &b.vec[i]);
        poly_add(r, &t);
    }
    poly_reduce(r);
}

/// Name:  polyvec_reduce
///
/// Description: Applies Barrett reduction to each coefficient
///  of each element of a vector of polynomials
///  for details of the Barrett reduction see comments in reduce.c
///
/// Arguments:   - poly *r:   input/output polynomial
pub fn polyvec_reduce(r: &mut Polyvec) {
    for i in 0..KYBER_K {
        poly_reduce(&mut r.vec[i]);
    }
}

/// Name:  polyvec_add
///
/// Description: Add vectors of polynomials
///
/// Arguments: - Polyvec r:   output vector of polynomials
///  - const Polyvec b: second input vector of polynomials
pub fn polyvec_add(r: &mut Polyvec, b: &Polyvec) {
    for i in 0..KYBER_K {
        poly_add(&mut r.vec[i], &b.vec[i]);
    }
}
