use crate::params::KYBER_Q;

const R: u128 = 1u128 << 64;
const R_MASK: u128 = R - 1;
// -q^{-1} mod R
const QINV: u128 = 1695300616315495935;

#[inline]
pub fn montgomery_reduce(a: u128) -> i128 {
    let a_lo = a & R_MASK;
    let a_hi = a >> 64;

    let t = (a_lo.wrapping_mul(QINV)) & R_MASK;
    let mq = t.wrapping_mul(KYBER_Q as u128);
    let mq_lo = mq & R_MASK;
    let mq_hi = mq >> 64;

    // Compute carry from 64-bit addition: (a_lo + mq_lo) >> 64
    let sum_lo = a_lo + mq_lo;
    let carry = sum_lo >> 64;
    let sum_hi = a_hi + mq_hi + carry;

    let mut res = sum_hi; // low limb cancels
    if res >= KYBER_Q as u128 {
        res -= KYBER_Q as u128;
    }
    res as i128
}

#[inline]
pub fn barrett_reduce(a: i128) -> i128 {
    let mut r = a % KYBER_Q as i128;
    if r < 0 {
        r += KYBER_Q as i128;
    }
    r
}

#[inline]
pub fn mul_mod(a: i128, b: i128) -> i128 {
    let aa = ((a % KYBER_Q as i128) + KYBER_Q as i128) as u128 % KYBER_Q as u128;
    let bb = ((b % KYBER_Q as i128) + KYBER_Q as i128) as u128 % KYBER_Q as u128;
    ((aa.wrapping_mul(bb)) % KYBER_Q as u128) as i128
}
