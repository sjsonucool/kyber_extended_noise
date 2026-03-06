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
    poly_getnoise_uniform_bounded(r, seed, nonce, KYBER_EPP_UNIFORM_BOUND);
}

pub(crate) fn poly_getnoise_uniform_bounded(r: &mut Poly, seed: &[u8], nonce: u8, bound: i128) {
    const BYTES_PER_COEFF: usize = 8; // enough to sample up to 2*B < 2^63
    const BUF_SIZE: usize = KYBER_N * BYTES_PER_COEFF * 2;
    let mut buf = [0u8; BUF_SIZE];
    let mut buf_pos = 0usize;
    debug_assert!(bound > 0);
    let range: u128 = (2 * bound) as u128;

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
            let reduced = val % range;
            // acceptance is trivial after modulus
            r.coeffs[i] = reduced as i128 - bound;
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
    #[inline]
    fn basemul_pair(a0: i128, a1: i128, b0: i128, b1: i128, zeta: i128) -> (i128, i128) {
        let t0 = crate::reference::ntt::fqmul(a1, b1);
        let t1 = crate::reference::ntt::fqmul(t0, zeta);
        let r0 = barrett_reduce(t1 + crate::reference::ntt::fqmul(a0, b0));
        let r1 = barrett_reduce(
            crate::reference::ntt::fqmul(a0, b1) + crate::reference::ntt::fqmul(a1, b0),
        );
        (r0, r1)
    }

    for i in 0..(KYBER_N / 4) {
        let idx = 4 * i;
        let zeta = crate::reference::ntt::zeta_at(64 + i);
        let (r0, r1) = basemul_pair(
            a.coeffs[idx],
            a.coeffs[idx + 1],
            b.coeffs[idx],
            b.coeffs[idx + 1],
            zeta,
        );
        let (r2, r3) = basemul_pair(
            a.coeffs[idx + 2],
            a.coeffs[idx + 3],
            b.coeffs[idx + 2],
            b.coeffs[idx + 3],
            barrett_reduce(-zeta),
        );
        r.coeffs[idx] = r0;
        r.coeffs[idx + 1] = r1;
        r.coeffs[idx + 2] = r2;
        r.coeffs[idx + 3] = r3;
    }
}

/// Name:  poly_tomont
///
/// Description: Inplace conversion of all coefficients of a polynomial
///  from normal domain to Montgomery domain
///
/// Arguments:   - poly *r:   input/output polynomial
pub fn poly_tomont(r: &mut Poly) {
    // Convert each coefficient to Montgomery domain: a * R^2 mod q.
    const R: u128 = 1u128 << 64;
    const R2: u128 = (R % KYBER_Q as u128) * (R % KYBER_Q as u128) % KYBER_Q as u128;
    for c in r.coeffs.iter_mut() {
        let a = ((*c % KYBER_Q as i128 + KYBER_Q as i128) as u128) % KYBER_Q as u128;
        *c = crate::reduce::montgomery_reduce(a.wrapping_mul(R2));
    }
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

#[cfg(test)]
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

/// Convert Montgomery domain coefficients back to normal domain in place.
pub fn poly_frommont(r: &mut Poly) {
    // Map Montgomery residues back to the standard representation.
    for c in r.coeffs.iter_mut() {
        *c = crate::reduce::montgomery_reduce(*c as u128);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, Rng, SeedableRng};

    #[test]
    fn ntt_mul_matches_schoolbook() {
        let mut rng = StdRng::seed_from_u64(424242);
        for _ in 0..2 {
            let mut a = Poly::new();
            let mut b = Poly::new();
            for c in a.coeffs.iter_mut() {
                *c = rng.gen_range(0..KYBER_Q as i128);
            }
            for c in b.coeffs.iter_mut() {
                *c = rng.gen_range(0..KYBER_Q as i128);
            }

            let mut want = Poly::new();
            poly_mul_negacyclic(&mut want, &a, &b);
            poly_reduce(&mut want);

            let mut an = a;
            let mut bn = b;
            poly_tomont(&mut an);
            poly_tomont(&mut bn);
            poly_ntt(&mut an);
            poly_ntt(&mut bn);

            let mut got = Poly::new();
            poly_basemul(&mut got, &an, &bn);
            poly_invntt_tomont(&mut got);
            poly_frommont(&mut got);
            poly_reduce(&mut got);

            for i in 0..KYBER_N {
                assert_eq!(
                    barrett_reduce(got.coeffs[i] - want.coeffs[i]),
                    0,
                    "mismatch at coeff {}",
                    i
                );
            }
        }
    }
}
