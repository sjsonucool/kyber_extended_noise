use crate::{cbd::*, ntt::*, params::*, reduce::*, symmetric::*};

#[derive(Clone)]
pub struct Poly {
    pub coeffs: [i128; KYBER_N],
}

impl Copy for Poly {}

impl Default for Poly {
    fn default() -> Self {
        Poly {
            coeffs: [0i128; KYBER_N],
        }
    }
}

// new() is nicer
impl Poly {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Name:  poly_compress
///
/// Description: Compression and subsequent serialization of a polynomial
///
/// Arguments:   - [u8] r: output byte array (needs space for KYBER_POLYCOMPRESSEDBYTES bytes)
///  - const poly *a:  input polynomial
pub fn poly_compress(r: &mut [u8], a: Poly) {
    poly_tobytes(r, a);
}

/// Name:  poly_decompress
///
/// Description: De-serialization and subsequent decompression of a polynomial;
///  approximate inverse of poly_compress
///
/// Arguments:   - poly *r:  output polynomial
///  - const [u8] a: input byte array (of length KYBER_POLYCOMPRESSEDBYTES bytes)
pub fn poly_decompress(r: &mut Poly, a: &[u8]) {
    poly_frombytes(r, a);
}

/// Name:  poly_tobytes
///
/// Description: Serialization of a polynomial
///
/// Arguments:   - [u8] r: output byte array (needs space for KYBER_POLYBYTES bytes)
///  - const poly *a:  input polynomial
pub fn poly_tobytes(r: &mut [u8], a: Poly) {
    for i in 0..KYBER_N {
        let mut v = a.coeffs[i] % KYBER_Q as i128;
        if v < 0 {
            v += KYBER_Q as i128;
        }
        let bytes = (v as u64).to_le_bytes();
        r[i * 8..i * 8 + 8].copy_from_slice(&bytes);
    }
}

/// Name:  poly_frombytes
///
/// Description: De-serialization of a polynomial;
///  inverse of poly_tobytes
///
/// Arguments:   - poly *r:  output polynomial
///  - const [u8] a: input byte array (of KYBER_POLYBYTES bytes)
pub fn poly_frombytes(r: &mut Poly, a: &[u8]) {
    for i in 0..KYBER_N {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&a[i * 8..i * 8 + 8]);
        r.coeffs[i] = u64::from_le_bytes(buf) as i128;
    }
}

/// Name:  poly_getnoise_eta1
///
/// Description: Sample a polynomial deterministically from a seed and a nonce,
///  with output polynomial close to centered binomial distribution
///  with parameter KYBER_ETA1
///
/// Arguments:   - poly *r:     output polynomial
///  - const [u8] seed: input seed (pointing to array of length KYBER_SYMBYTES bytes)
///  - [u8]  nonce:   one-byte input nonce
pub fn poly_getnoise_eta1(r: &mut Poly, seed: &[u8], nonce: u8) {
    const LENGTH: usize = KYBER_ETA1 * KYBER_N / 4;
    let mut buf = [0u8; LENGTH];
    prf(&mut buf, LENGTH, seed, nonce);
    poly_cbd_eta1(r, &buf);
}

/// Name:  poly_getnoise_eta2
///
/// Description: Sample a polynomial deterministically from a seed and a nonce,
///  with output polynomial close to centered binomial distribution
///  with parameter KYBER_ETA2
///
/// Arguments:   - poly *r:     output polynomial
///  - const [u8] seed: input seed (pointing to array of length KYBER_SYMBYTES bytes)
///  - [u8]  nonce:   one-byte input nonce
pub fn poly_getnoise_eta2(r: &mut Poly, seed: &[u8], nonce: u8) {
    const LENGTH: usize = KYBER_ETA2 * KYBER_N / 4;
    let mut buf = [0u8; LENGTH];
    prf(&mut buf, LENGTH, seed, nonce);
    poly_cbd_eta2(r, &buf);
}

/// Name:  poly_getnoise_uniform
///
/// Description: Sample a polynomial deterministically from a seed and a nonce,
///  with output polynomial coefficients uniformly distributed in 
///  [-KYBER_EPP_UNIFORM_BOUND, KYBER_EPP_UNIFORM_BOUND)
///
/// Arguments:   - poly *r:     output polynomial
///  - const [u8] seed: input seed (pointing to array of length KYBER_SYMBYTES bytes)
///  - [u8]  nonce:   one-byte input nonce
pub fn poly_getnoise_uniform(r: &mut Poly, seed: &[u8], nonce: u8) {
    const RANGE: u128 = (2 * KYBER_EPP_UNIFORM_BOUND) as u128;
    const BYTES_PER_COEFF: usize = 8; // enough to sample up to 2*B < 2^63
    const BUF_SIZE: usize = KYBER_N * BYTES_PER_COEFF * 2;
    let mut buf = [0u8; BUF_SIZE];
    let mut buf_pos = 0usize;

    prf(&mut buf, BUF_SIZE, seed, nonce);

    for i in 0..KYBER_N {
        loop {
            if buf_pos + BYTES_PER_COEFF > BUF_SIZE {
                // reseed with nonce stride
                let mut refill = [0u8; BYTES_PER_COEFF * 4];
                let refill_len = refill.len();
                prf(&mut refill, refill_len, seed, nonce.wrapping_add(i as u8));
                buf[..refill_len].copy_from_slice(&refill);
                buf_pos = 0;
            }
            let mut slice = [0u8; 16];
            slice[..8].copy_from_slice(&buf[buf_pos..buf_pos + BYTES_PER_COEFF]);
            buf_pos += BYTES_PER_COEFF;
            let val = u128::from_le_bytes(slice);
            let reduced = val % RANGE;
            // acceptance is trivial after modulus
            r.coeffs[i] = reduced as i128 - KYBER_EPP_UNIFORM_BOUND;
            break;
        }
    }
}

/// Name:  poly_ntt
///
/// Description: Computes negacyclic number-theoretic transform (NTT) of
///  a polynomial in place;
///  inputs assumed to be in normal order, output in bitreversed order
///
/// Arguments:   - Poly r: in/output polynomial
pub fn poly_ntt(r: &mut Poly) {
    ntt(&mut r.coeffs);
}

/// Name:  poly_invntt
///
/// Description: Computes inverse of negacyclic number-theoretic transform (NTT) of
///  a polynomial in place;
///  inputs assumed to be in bitreversed order, output in normal order
///
/// Arguments:   - Poly a: in/output polynomial
pub fn poly_invntt_tomont(r: &mut Poly) {
    invntt(&mut r.coeffs);
}

/// Name:  poly_basemul
///
/// Description: Multiplication of two polynomials in NTT domain
///
/// Arguments:   - poly *r:   output polynomial
///  - const poly *a: first input polynomial
///  - const poly *b: second input polynomial
pub fn poly_basemul(r: &mut Poly, a: &Poly, b: &Poly) {
    poly_mul_negacyclic(r, a, b);
}

/// Name:  poly_tomont
///
/// Description: Inplace conversion of all coefficients of a polynomial
///  from normal domain to Montgomery domain
///
/// Arguments:   - poly *r:   input/output polynomial
pub fn poly_tomont(_r: &mut Poly) {
    // No-op for schoolbook path.
}

/// Name:  poly_reduce
///
/// Description: Applies Barrett reduction to all coefficients of a polynomial
///  for details of the Barrett reduction see comments in reduce.c
///
/// Arguments:   - poly *r:   input/output polynomial
pub fn poly_reduce(r: &mut Poly) {
    for c in r.coeffs.iter_mut() {
        *c = barrett_reduce(*c);
    }
}

/// Name:  poly_add
///
/// Description: Add two polynomials; no modular reduction is performed
///
/// Arguments: - poly *r:   output polynomial
///  - const poly *a: first input polynomial
///  - const poly *b: second input polynomial
pub fn poly_add(r: &mut Poly, b: &Poly) {
    for i in 0..KYBER_N {
        r.coeffs[i] += b.coeffs[i];
    }
}

/// Name:  poly_sub
///
/// Description: Subtract two polynomials; no modular reduction is performed
///
/// Arguments: - poly *r:   output polynomial
///  - const poly *a: first input polynomial
///  - const poly *b: second input polynomial
pub fn poly_sub(r: &mut Poly, a: &Poly) {
    for i in 0..KYBER_N {
        r.coeffs[i] = r.coeffs[i] - a.coeffs[i];
    }
}

pub(crate) fn poly_mul_negacyclic(r: &mut Poly, a: &Poly, b: &Poly) {
    let mut tmp = [0i128; KYBER_N];
    for i in 0..KYBER_N {
        let ai = a.coeffs[i];
        for j in 0..KYBER_N {
            let prod = mul_mod(ai, b.coeffs[j]);
            let k = i + j;
            if k < KYBER_N {
                tmp[k] = barrett_reduce(tmp[k] + prod);
            } else {
                // x^{N} == -1 mod (x^N + 1)
                let idx = k - KYBER_N;
                tmp[idx] = barrett_reduce(tmp[idx] - prod);
            }
        }
    }
    r.coeffs = tmp;
}

/// Name:  poly_frommsg
///
/// Description: Convert `KYBER_SYMBYTES`-byte message to polynomial
///
/// Arguments:   - poly *r:    output polynomial
///  - const [u8] msg: input message (of length KYBER_SYMBYTES)
pub fn poly_frommsg(r: &mut Poly, msg: &[u8]) {
    let half_q = ((KYBER_Q + 1) / 2) as i128;
    for i in 0..KYBER_N / 8 {
        for j in 0..8 {
            let bit = ((msg[i] >> j) & 1) as i128;
            r.coeffs[8 * i + j] = if bit == 1 { half_q } else { 0 };
        }
    }
}

/// Name:  poly_tomsg
///
/// Description: Convert polynomial to 32-byte message
///
/// Arguments:   - [u8] msg: output message
///  - const poly *a:  input polynomial
pub fn poly_tomsg(msg: &mut [u8], a: Poly) {
    for i in 0..KYBER_N / 8 {
        msg[i] = 0;
        for j in 0..8 {
            let mut t = a.coeffs[8 * i + j] % KYBER_Q as i128;
            if t < 0 {
                t += KYBER_Q as i128;
            }
            t = (((t * 2) + (KYBER_Q as i128 / 2)) / KYBER_Q as i128) & 1;
            msg[i] |= (t as u8) << j;
        }
    }
}
