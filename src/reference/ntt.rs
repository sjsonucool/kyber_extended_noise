use crate::params::{KYBER_N, KYBER_Q};
use crate::reduce::{barrett_reduce, mul_mod};

// Primitive 512-th root of unity for q, so psi^256 = -1 and omega = psi^2 has order 256.
const PSI: i128 = 2_840_371_014_574_357_197;
const OMEGA: i128 = 4_914_799_530_725_508_435;

#[inline]
pub(crate) fn fqmul(a: i128, b: i128) -> i128 {
    mul_mod(a, b)
}

#[inline]
fn mod_pow(mut base: i128, mut exp: i128) -> i128 {
    let mut out = 1i128;
    base = barrett_reduce(base);
    while exp > 0 {
        if exp & 1 == 1 {
            out = mul_mod(out, base);
        }
        base = mul_mod(base, base);
        exp >>= 1;
    }
    out
}

#[inline]
fn pow_table(base: i128) -> [i128; KYBER_N] {
    let mut t = [0i128; KYBER_N];
    t[0] = 1;
    for i in 1..KYBER_N {
        t[i] = mul_mod(t[i - 1], base);
    }
    t
}

// Cooley-Tukey DIF negacyclic NTT with psi pre/post and O(N log N) cost.
// Forward: multiply by psi^i, then standard DIF NTT with root omega (order N).
pub fn ntt(r: &mut [i128]) {
    let psi_pow = pow_table(PSI);
    // chirp: embed negacyclic factor
    for i in 0..KYBER_N {
        r[i] = mul_mod(r[i], psi_pow[i]);
    }

    let mut len = KYBER_N / 2;
    while len >= 1 {
        // twiddle step for this layer
        let w_m = mod_pow(OMEGA, (KYBER_N / (2 * len)) as i128);
        for start in (0..KYBER_N).step_by(2 * len) {
            let mut w = 1i128;
            for j in 0..len {
                let u = r[start + j];
                let v = mul_mod(r[start + j + len], w);
                r[start + j] = barrett_reduce(u + v);
                r[start + j + len] = barrett_reduce(u - v);
                w = mul_mod(w, w_m);
            }
        }
        len >>= 1;
    }
}

// Inverse: Gentleman-Sande style (iterative length doubling), then de-chirp and scale.
pub fn invntt(r: &mut [i128]) {
    let q = KYBER_Q as i128;
    let inv_omega = mod_pow(OMEGA, q - 2);
    let inv_psi = mod_pow(PSI, q - 2);
    let inv_psi_pow = pow_table(inv_psi);
    let inv_n = mod_pow(KYBER_N as i128, q - 2);

    let mut len = 1;
    while len < KYBER_N {
        let w_m = mod_pow(inv_omega, (KYBER_N / (2 * len)) as i128);
        for start in (0..KYBER_N).step_by(2 * len) {
            let mut w = 1i128;
            for j in 0..len {
                let u = r[start + j];
                let v = r[start + j + len];
                r[start + j] = barrett_reduce(u + v);
                r[start + j + len] = mul_mod(barrett_reduce(u - v), w);
                w = mul_mod(w, w_m);
            }
        }
        len <<= 1;
    }

    // scale by 1/N and remove chirp
    for i in 0..KYBER_N {
        r[i] = mul_mod(mul_mod(r[i], inv_n), inv_psi_pow[i]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, Rng, SeedableRng};

    #[test]
    fn ntt_inv_roundtrip() {
        let mut rng = StdRng::seed_from_u64(123);
        for _ in 0..2 {
            let mut a = [0i128; KYBER_N];
            for v in a.iter_mut() {
                *v = rng.gen_range(0..KYBER_Q as i128);
            }
            let orig = a;
            ntt(&mut a);
            invntt(&mut a);
            for i in 0..KYBER_N {
                assert_eq!(barrett_reduce(orig[i] - a[i]), 0, "idx {}", i);
            }
        }
    }
}
