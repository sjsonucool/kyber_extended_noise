use crate::params::KYBER_Q;

const R: u128 = 1u128 << 64;
const R_MASK: u128 = R - 1;
const Q_U128: u128 = KYBER_Q as u128;
const Q_U64: u64 = KYBER_Q as u64;
const TWO64_MINUS_Q: u64 = ((1u128 << 64) - Q_U128) as u64;
const Q_I128: i128 = KYBER_Q as i128;
// -q^{-1} mod R
const QINV: u128 = 1695300616315495935;

#[inline]
pub fn montgomery_reduce(a: u128) -> u64 {
    let a_lo = a & R_MASK;
    let a_hi = a >> 64;

    let t = (a_lo.wrapping_mul(QINV)) & R_MASK;
    let mq = t.wrapping_mul(Q_U128);
    let mq_lo = mq & R_MASK;
    let mq_hi = mq >> 64;

    // Compute carry from 64-bit addition: (a_lo + mq_lo) >> 64
    let sum_lo = a_lo + mq_lo;
    let carry = sum_lo >> 64;
    let sum_hi = a_hi + mq_hi + carry;

    let mut res = sum_hi; // low limb cancels
    if res >= Q_U128 {
        res -= Q_U128;
    }
    res as u64
}

#[inline]
pub fn barrett_reduce(a: i128) -> u64 {
    let mut r = a % Q_I128;
    if r < 0 {
        r += Q_I128;
    }
    r as u64
}

/// Fast modular add assuming a,b are already in [0,q).
#[inline]
pub fn add_mod(a: u64, b: u64) -> u64 {
    debug_assert!(a < Q_U64);
    debug_assert!(b < Q_U64);
    let (sum, carry) = a.overflowing_add(b);
    if carry {
        // (a + b) - q = (a + b - 2^64) + (2^64 - q)
        sum + TWO64_MINUS_Q
    } else if sum >= Q_U64 {
        sum - Q_U64
    } else {
        sum
    }
}

/// Fast modular sub assuming a,b are already in [0,q).
#[inline]
pub fn sub_mod(a: u64, b: u64) -> u64 {
    debug_assert!(a < Q_U64);
    debug_assert!(b < Q_U64);
    let mut r = a.wrapping_sub(b);
    if a < b {
        r = r.wrapping_add(Q_U64);
    }
    r
}

/// Map a centered signed representative into [0,q).
#[inline]
pub fn centered_to_mod_q(x: i128) -> u64 {
    debug_assert!(x > -(Q_I128) && x < Q_I128);
    if x >= 0 {
        x as u64
    } else {
        let neg = (-x) as u64;
        if neg == 0 { 0 } else { Q_U64 - neg }
    }
}

#[inline]
pub fn mul_mod(a: u64, b: u64) -> u64 {
    ((a as u128).wrapping_mul(b as u128) % Q_U128) as u64
}
