use crate::rng::randombytes;
use crate::{params::*, poly::*, polyvec::*, symmetric::*, CryptoRng, KyberError, RngCore};

/// Name:  pack_pk
///
/// Description: Serialize the public key as concatenation of the
///  serialized vector of polynomials pk
///  and the public seed used to generate the matrix A.
///
/// Arguments:   [u8] r:  the output serialized public key
///  const poly *pk:  the input public-key polynomial
///  const [u8] seed: the input public seed
fn pack_pk(r: &mut [u8], pk: &mut Polyvec, seed: &[u8]) {
    const END: usize = KYBER_SYMBYTES + KYBER_POLYVECBYTES;
    polyvec_tobytes(r, pk);
    r[KYBER_POLYVECBYTES..END].copy_from_slice(&seed[..KYBER_SYMBYTES]);
}

/// Name:  unpack_pk
///
/// Description: De-serialize public key from a byte array;
///  approximate inverse of pack_pk
///
/// Arguments:   - Polyvec pk:  output public-key vector of polynomials
///  - [u8] seed:   output seed to generate matrix A
///  - const [u8] packedpk: input serialized public key
fn unpack_pk(pk: &mut Polyvec, seed: &mut [u8], packedpk: &[u8]) {
    const END: usize = KYBER_SYMBYTES + KYBER_POLYVECBYTES;
    polyvec_frombytes(pk, packedpk);
    seed[..KYBER_SYMBYTES].copy_from_slice(&packedpk[KYBER_POLYVECBYTES..END]);
}

/// Name:  pack_sk
///
/// Description: Serialize the secret key
///
/// Arguments: - [u8] r:  output serialized secret key
///  - const Polyvec sk: input vector of polynomials (secret key)
fn pack_sk(r: &mut [u8], sk: &mut Polyvec) {
    polyvec_tobytes(r, sk);
}

/// Name:  unpack_sk
///
/// Description: De-serialize the secret key, inverse of pack_sk
///
/// Arguments:   - Polyvec sk: output vector of polynomials (secret key)
///  - const [u8] packedsk: input serialized secret key
fn unpack_sk(sk: &mut Polyvec, packedsk: &[u8]) {
    polyvec_frombytes(sk, packedsk);
}

/// Name:  pack_ciphertext
///
/// Description: Serialize the ciphertext as concatenation of the
///  compressed and serialized vector of polynomials b
///  and the compressed and serialized polynomial v
///
/// Arguments:   [u8] r:  the output serialized ciphertext
///  const poly *pk:  the input vector of polynomials b
///  const [u8] seed: the input polynomial v
fn pack_ciphertext(r: &mut [u8], b: &mut Polyvec, v: Poly) {
    polyvec_compress(r, *b);
    poly_compress(&mut r[KYBER_POLYVECCOMPRESSEDBYTES..], v);
}

/// Name:  unpack_ciphertext
///
/// Description: De-serialize and decompress ciphertext from a byte array;
///  approximate inverse of pack_ciphertext
///
/// Arguments:   - Polyvec b:   output vector of polynomials b
///  - poly *v:  output polynomial v
///  - const [u8] c:   input serialized ciphertext
fn unpack_ciphertext(b: &mut Polyvec, v: &mut Poly, c: &[u8]) {
    polyvec_decompress(b, c);
    poly_decompress(v, &c[KYBER_POLYVECCOMPRESSEDBYTES..]);
}

/// Name:  rej_uniform
///
/// Description: Run rejection sampling on uniform random bytes to generate
///  uniform random integers mod q
///
/// Arguments: - i16 *r:  output buffer
///  - usize len:   requested number of 16-bit integers (uniform mod q)
///  - const [u8] buf:  input buffer (assumed to be uniform random bytes)
///  - usize buflen:  length of input buffer in bytes
///
/// Returns number of sampled 16-bit integers (at most len)
fn gen_a(a: &mut [Polyvec], b: &[u8]) {
    gen_matrix(a, b, false);
}

fn gen_at(a: &mut [Polyvec], b: &[u8]) {
    gen_matrix(a, b, true);
}

/// Name:  gen_matrix
///
/// Description: Deterministically generate matrix A (or the transpose of A)
///  from a seed. Entries of the matrix are polynomials that look
///  uniformly random. Performs rejection sampling on output of
///  a XOF
///
/// Arguments:   - Polyvec a:   ouptput matrix A
///  - const [u8] seed: input seed
///  - bool transposed: boolean deciding whether A or A^T is generated
fn gen_matrix(a: &mut [Polyvec], seed: &[u8], transposed: bool) {
    let mut state = XofState::new();
    let mut buf = [0u8; XOF_BLOCKBYTES];
    let mut buf_pos = XOF_BLOCKBYTES; // force initial squeeze

    for i in 0..KYBER_K {
        for j in 0..KYBER_K {
            if transposed {
                xof_absorb(&mut state, seed, i as u8, j as u8);
            } else {
                xof_absorb(&mut state, seed, j as u8, i as u8);
            }
            // Reset buffer position so the new absorb starts with a fresh squeeze.
            buf_pos = XOF_BLOCKBYTES;
            for coeff in a[i].vec[j].coeffs.iter_mut().take(KYBER_N) {
                let mut bytes = [0u8; 16];
                for b in 0..16 {
                    if buf_pos >= XOF_BLOCKBYTES {
                        xof_squeezeblocks(&mut buf, 1, &mut state);
                        buf_pos = 0;
                    }
                    bytes[b] = buf[buf_pos];
                    buf_pos += 1;
                }
                let val = u128::from_le_bytes(bytes);
                *coeff = (val % KYBER_Q) as i128;
            }
            // Match the original Kyber workflow: store A (and A^T) directly in
            // NTT/Montgomery domain so later basemul operates on NTT inputs.
            poly_ntt(&mut a[i].vec[j]);
        }
    }
}

// Name:  indcpa_keypair
//
// Description: Generates public and private key for the CPA-secure
//  public-key encryption scheme underlying Kyber
//
// Arguments: - [u8] pk: output public key (length KYBER_INDCPA_PUBLICKEYBYTES)
//  - [u8] sk: output private key (length KYBER_INDCPA_SECRETKEYBYTES)
pub fn indcpa_keypair<R>(
    pk: &mut [u8],
    sk: &mut [u8],
    _seed: Option<(&[u8], &[u8])>,
    _rng: &mut R,
) -> Result<(), KyberError>
where
    R: CryptoRng + RngCore,
{
    let mut a = [Polyvec::new(); KYBER_K];
    let (mut e, mut pkpv, mut skpv) = (Polyvec::new(), Polyvec::new(), Polyvec::new());
    let mut nonce = 0u8;
    let mut buf = [0u8; 2 * KYBER_SYMBYTES];
    let mut randbuf = [0u8; 2 * KYBER_SYMBYTES];

    if let Some(s) = _seed {
        randbuf[..KYBER_SYMBYTES].copy_from_slice(&s.0);
    } else {
        randombytes(&mut randbuf, KYBER_SYMBYTES, _rng)?;
    }

    hash_g(&mut buf, &randbuf, KYBER_SYMBYTES);

    let (publicseed, noiseseed) = buf.split_at(KYBER_SYMBYTES);
    gen_a(&mut a, publicseed);

    for i in 0..KYBER_K {
        poly_getnoise_eta1(&mut skpv.vec[i], noiseseed, nonce);
        nonce += 1;
    }
    for i in 0..KYBER_K {
        poly_getnoise_eta1(&mut e.vec[i], noiseseed, nonce);
        nonce += 1;
    }

    polyvec_ntt(&mut skpv);
    polyvec_ntt(&mut e);

    // matrix-vector multiplication
    for i in 0..KYBER_K {
        polyvec_basemul_acc_montgomery(&mut pkpv.vec[i], &a[i], &skpv);
        poly_tomont(&mut pkpv.vec[i]);
    }
    polyvec_add(&mut pkpv, &e);
    polyvec_reduce(&mut pkpv);

    pack_sk(sk, &mut skpv);
    pack_pk(pk, &mut pkpv, publicseed);
    Ok(())
}

/// Name:  indcpa_enc
///
/// Description: Encryption function of the CPA-secure
///  public-key encryption scheme underlying Kyber.
///
/// Arguments: - [u8] c:  output ciphertext (length KYBER_INDCPA_BYTES)
///  - const [u8] m:  input message (length KYBER_SYMBYTES)
///  - const [u8] pk:   input public key (length KYBER_INDCPA_PUBLICKEYBYTES)
///  - const [u8] coin: input random coins used as seed (length KYBER_SYMBYTES)
///      to deterministically generate all randomness
pub fn indcpa_enc(c: &mut [u8], m: &[u8], pk: &[u8], coins: &[u8]) {
    let mut at = [Polyvec::new(); KYBER_K];
    let (mut sp, mut pkpv, mut ep, mut b) = (
        Polyvec::new(),
        Polyvec::new(),
        Polyvec::new(),
        Polyvec::new(),
    );
    let (mut v, mut k, mut epp) = (Poly::new(), Poly::new(), Poly::new());
    let mut seed = [0u8; KYBER_SYMBYTES];
    let mut nonce = 0u8;

    unpack_pk(&mut pkpv, &mut seed, pk);
    poly_frommsg(&mut k, m);
    gen_at(&mut at, &seed);

    for i in 0..KYBER_K {
        poly_getnoise_eta1(&mut sp.vec[i], coins, nonce);
        nonce += 1;
    }
    for i in 0..KYBER_K {
        poly_getnoise_eta2(&mut ep.vec[i], coins, nonce);
        nonce += 1;
    }
    // Use uniform distribution for epp instead of centered binomial
    poly_getnoise_uniform(&mut epp, coins, nonce);

    polyvec_ntt(&mut sp);

    // matrix-vector multiplication
    for i in 0..KYBER_K {
        polyvec_basemul_acc_montgomery(&mut b.vec[i], &at[i], &sp);
    }

    polyvec_basemul_acc_montgomery(&mut v, &pkpv, &sp);
    polyvec_invntt_tomont(&mut b);
    poly_invntt_tomont(&mut v);

    polyvec_add(&mut b, &ep);
    poly_add(&mut v, &epp);
    poly_add(&mut v, &k);
    polyvec_reduce(&mut b);
    poly_reduce(&mut v);

    pack_ciphertext(c, &mut b, v);
}

/// Name:  indcpa_dec
///
/// Description: Decryption function of the CPA-secure
///  public-key encryption scheme underlying Kyber.
///
/// Arguments:   - [u8] m:  output decrypted message (of length KYBER_SYMBYTES)
///  - const [u8] c:  input ciphertext (of length KYBER_INDCPA_BYTES)
///  - const [u8] sk: input secret key (of length KYBER_INDCPA_SECRETKEYBYTES)
pub fn indcpa_dec(m: &mut [u8], c: &[u8], sk: &[u8]) {
    let (mut b, mut skpv) = (Polyvec::new(), Polyvec::new());
    let (mut v, mut mp) = (Poly::new(), Poly::new());

    unpack_ciphertext(&mut b, &mut v, c);
    unpack_sk(&mut skpv, sk);

    polyvec_ntt(&mut b);
    polyvec_basemul_acc_montgomery(&mut mp, &skpv, &b);
    poly_invntt_tomont(&mut mp);

    poly_sub(&mut mp, &v);
    poly_reduce(&mut mp);

    poly_tomsg(m, mp);
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, RngCore, SeedableRng};

    #[test]
    fn indcpa_roundtrip() {
        let mut rng = StdRng::seed_from_u64(7);
        let mut pk = [0u8; KYBER_INDCPA_PUBLICKEYBYTES];
        let mut sk = [0u8; KYBER_INDCPA_SECRETKEYBYTES];
        indcpa_keypair(&mut pk, &mut sk, None, &mut rng).unwrap();

        let mut m = [0u8; KYBER_SYMBYTES];
        rng.fill_bytes(&mut m);
        let mut coins = [0u8; KYBER_SYMBYTES];
        rng.fill_bytes(&mut coins);

        let mut c = [0u8; KYBER_INDCPA_BYTES];
        indcpa_enc(&mut c, &m, &pk, &coins);

        let mut m_dec = [0u8; KYBER_SYMBYTES];
        indcpa_dec(&mut m_dec, &c, &sk);

        if m != m_dec {
            // Re-run decryption inline to inspect the failing polynomial.
            let mut b = Polyvec::new();
            let mut v = Poly::new();
            unpack_ciphertext(&mut b, &mut v, &c);
            let mut skpv = Polyvec::new();
            unpack_sk(&mut skpv, &sk);
            polyvec_ntt(&mut b);
            let mut mp = Poly::new();
            polyvec_basemul_acc_montgomery(&mut mp, &skpv, &b);
            poly_invntt_tomont(&mut mp);
            poly_sub(&mut mp, &v);
            poly_reduce(&mut mp);

            let half_q = ((KYBER_Q + 1) / 2) as i128;
            let mut close_to_half = 0usize;
            for c in mp.coeffs.iter() {
                let mut t = *c % KYBER_Q as i128;
                if t < 0 {
                    t += KYBER_Q as i128;
                }
                if (t - half_q).abs() < 50 {
                    close_to_half += 1;
                }
            }
            panic!(
                "message mismatch: orig={:?} dec={:?}, coeffs near q/2: {}",
                &m[..4],
                &m_dec[..4],
                close_to_half
            );
        }
    }
}
