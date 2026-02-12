use crate::reduce::barrett_reduce;

/// Placeholder NTT for the schoolbook path: just ensure coefficients are reduced.
pub fn ntt(r: &mut [i128]) {
    for v in r.iter_mut() {
        *v = barrett_reduce(*v);
    }
}

/// Placeholder inverse NTT for the schoolbook path.
pub fn invntt(r: &mut [i128]) {
    for v in r.iter_mut() {
        *v = barrett_reduce(*v);
    }
}
