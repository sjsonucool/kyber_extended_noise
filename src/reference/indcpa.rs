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
    // store pk in normal domain
    polyvec_invntt_tomont(pk);
    polyvec_frommont(pk);
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
    // move to Montgomery+NTT for use
    polyvec_tomont(pk);
    polyvec_ntt(pk);
}

/// Name:  pack_sk
///
/// Description: Serialize the secret key
///
/// Arguments: - [u8] r:  output serialized secret key
///  - const Polyvec sk: input vector of polynomials (secret key)
fn pack_sk(r: &mut [u8], sk: &mut Polyvec) {
    polyvec_invntt_tomont(sk);
    polyvec_frommont(sk);
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
    polyvec_tomont(sk);
    polyvec_ntt(sk);
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
    let mut b_norm = b.clone();
    polyvec_frommont(&mut b_norm);
    let mut v_norm = v;
    poly_frommont(&mut v_norm);
    polyvec_compress(r, b_norm);
    poly_compress(&mut r[KYBER_POLYVECCOMPRESSEDBYTES..], v_norm);
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
    let mut buf_pos: usize;

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
                *coeff = (val % KYBER_Q) as u64;
            }
            // Move to Montgomery then NTT so later basemul sees Montgomery inputs.
            poly_tomont(&mut a[i].vec[j]);
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
        poly_tomont(&mut skpv.vec[i]);
    }
    for i in 0..KYBER_K {
        poly_getnoise_eta1(&mut e.vec[i], noiseseed, nonce);
        nonce += 1;
        poly_tomont(&mut e.vec[i]);
    }

    polyvec_ntt(&mut skpv);
    polyvec_ntt(&mut e);

    // matrix-vector multiplication
    for i in 0..KYBER_K {
        polyvec_basemul_acc_montgomery(&mut pkpv.vec[i], &a[i], &skpv);
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
pub(crate) fn indcpa_enc_inner(
    c: &mut [u8],
    m: &[u8],
    pk: &[u8],
    coins: &[u8],
    epp_bound: i128,
) {
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
    poly_tomont(&mut k);
    gen_at(&mut at, &seed);

    for i in 0..KYBER_K {
        poly_getnoise_eta1(&mut sp.vec[i], coins, nonce);
        nonce += 1;
        poly_tomont(&mut sp.vec[i]);
    }
    for i in 0..KYBER_K {
        poly_getnoise_eta2(&mut ep.vec[i], coins, nonce);
        nonce += 1;
        poly_tomont(&mut ep.vec[i]);
    }
    poly_getnoise_uniform_bounded(&mut epp, coins, nonce, epp_bound);
    poly_tomont(&mut epp);

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

pub fn indcpa_enc(c: &mut [u8], m: &[u8], pk: &[u8], coins: &[u8]) {
    indcpa_enc_inner(c, m, pk, coins, KYBER_EPP_UNIFORM_BOUND);
}

/// INDCPA encryption with an explicit bounded-uniform `epp` range.
///
/// This is intended for hazmat experiments (for example reliability sweeps
/// over candidate bounds) while the default API keeps using
/// `KYBER_EPP_UNIFORM_BOUND`.
#[cfg(feature = "hazmat")]
pub fn indcpa_enc_with_epp_bound(
    c: &mut [u8],
    m: &[u8],
    pk: &[u8],
    coins: &[u8],
    epp_bound: i128,
) {
    indcpa_enc_inner(c, m, pk, coins, epp_bound);
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

    polyvec_tomont(&mut b);
    polyvec_ntt(&mut b);
    polyvec_basemul_acc_montgomery(&mut mp, &skpv, &b);
    poly_invntt_tomont(&mut mp);
    poly_frommont(&mut mp);
    poly_sub(&mut mp, &v);
    poly_reduce(&mut mp);
    poly_tomsg(m, mp);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kem::{crypto_kem_dec_inner, crypto_kem_enc_inner, crypto_kem_keypair};
    use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};

    fn random_poly(rng: &mut StdRng) -> Poly {
        let mut p = Poly::new();
        for c in p.coeffs.iter_mut() {
            *c = rng.gen_range(0..KYBER_Q as u64);
        }
        p
    }

    fn random_polyvec(rng: &mut StdRng) -> Polyvec {
        let mut v = Polyvec::new();
        for i in 0..KYBER_K {
            v.vec[i] = random_poly(rng);
        }
        v
    }

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
        assert_eq!(m, m_dec);
    }

    #[test]
    fn pack_unpack_domain_symmetry() {
        let mut rng = StdRng::seed_from_u64(777);

        let mut pk_ntt = random_polyvec(&mut rng);
        polyvec_tomont(&mut pk_ntt);
        polyvec_ntt(&mut pk_ntt);
        let pk_ntt_orig = pk_ntt;
        let mut seed = [0u8; KYBER_SYMBYTES];
        rng.fill_bytes(&mut seed);
        let mut packed_pk = [0u8; KYBER_INDCPA_PUBLICKEYBYTES];
        pack_pk(&mut packed_pk, &mut pk_ntt, &seed);
        let mut unpacked_pk = Polyvec::new();
        let mut seed2 = [0u8; KYBER_SYMBYTES];
        unpack_pk(&mut unpacked_pk, &mut seed2, &packed_pk);
        assert_eq!(seed, seed2);
        for i in 0..KYBER_K {
            for j in 0..KYBER_N {
                assert_eq!(unpacked_pk.vec[i].coeffs[j], pk_ntt_orig.vec[i].coeffs[j]);
            }
        }
        let mut repacked_pk = [0u8; KYBER_INDCPA_PUBLICKEYBYTES];
        pack_pk(&mut repacked_pk, &mut unpacked_pk, &seed2);
        assert_eq!(packed_pk, repacked_pk);

        let mut sk_ntt = random_polyvec(&mut rng);
        polyvec_tomont(&mut sk_ntt);
        polyvec_ntt(&mut sk_ntt);
        let sk_ntt_orig = sk_ntt;
        let mut packed_sk = [0u8; KYBER_INDCPA_SECRETKEYBYTES];
        pack_sk(&mut packed_sk, &mut sk_ntt);
        let mut unpacked_sk = Polyvec::new();
        unpack_sk(&mut unpacked_sk, &packed_sk);
        for i in 0..KYBER_K {
            for j in 0..KYBER_N {
                assert_eq!(unpacked_sk.vec[i].coeffs[j], sk_ntt_orig.vec[i].coeffs[j]);
            }
        }
        let mut repacked_sk = [0u8; KYBER_INDCPA_SECRETKEYBYTES];
        pack_sk(&mut repacked_sk, &mut unpacked_sk);
        assert_eq!(packed_sk, repacked_sk);

        let b_norm = random_polyvec(&mut rng);
        let v_norm = random_poly(&mut rng);
        let mut b_mont = b_norm;
        let mut v_mont = v_norm;
        polyvec_tomont(&mut b_mont);
        poly_tomont(&mut v_mont);
        let mut packed_ct = [0u8; KYBER_INDCPA_BYTES];
        pack_ciphertext(&mut packed_ct, &mut b_mont, v_mont);
        let mut b_out = Polyvec::new();
        let mut v_out = Poly::new();
        unpack_ciphertext(&mut b_out, &mut v_out, &packed_ct);
        for i in 0..KYBER_K {
            for j in 0..KYBER_N {
                assert_eq!(b_out.vec[i].coeffs[j], b_norm.vec[i].coeffs[j]);
            }
        }
        for j in 0..KYBER_N {
            assert_eq!(v_out.coeffs[j], v_norm.coeffs[j]);
        }
    }

    #[test]
    #[ignore = "Long-running diagnostic harness for selecting bounded-uniform epp support."]
    fn epp_bound_sweep_harness() {
        const CANDIDATES: [i128; 4] = [16, 20, 24, 32];
        const TRIALS: usize = 8;

        let mut largest_zero_fail_bound = CANDIDATES[0];

        for &bound in CANDIDATES.iter() {
            let mut indcpa_failures = 0usize;
            let mut kem_failures = 0usize;

            for t in 0..TRIALS {
                let mut rng = StdRng::seed_from_u64(0xB0AD_0000 + (bound as u64) * 131 + t as u64);

                let mut pk = [0u8; KYBER_INDCPA_PUBLICKEYBYTES];
                let mut sk = [0u8; KYBER_INDCPA_SECRETKEYBYTES];
                indcpa_keypair(&mut pk, &mut sk, None, &mut rng).unwrap();
                let mut m = [0u8; KYBER_SYMBYTES];
                let mut coins = [0u8; KYBER_SYMBYTES];
                rng.fill_bytes(&mut m);
                rng.fill_bytes(&mut coins);
                let mut c = [0u8; KYBER_INDCPA_BYTES];
                indcpa_enc_inner(&mut c, &m, &pk, &coins, bound);
                let mut m_dec = [0u8; KYBER_SYMBYTES];
                indcpa_dec(&mut m_dec, &c, &sk);
                if m != m_dec {
                    indcpa_failures += 1;
                }

                let mut kem_pk = [0u8; KYBER_PUBLICKEYBYTES];
                let mut kem_sk = [0u8; KYBER_SECRETKEYBYTES];
                crypto_kem_keypair(&mut kem_pk, &mut kem_sk, &mut rng, None).unwrap();
                let mut ct = [0u8; KYBER_CIPHERTEXTBYTES];
                let mut ss1 = [0u8; KYBER_SSBYTES];
                let mut ss2 = [0u8; KYBER_SSBYTES];
                crypto_kem_enc_inner(&mut ct, &mut ss1, &kem_pk, &mut rng, None, bound).unwrap();
                crypto_kem_dec_inner(&mut ss2, &ct, &kem_sk, bound);
                if ss1 != ss2 {
                    kem_failures += 1;
                }
            }

            if indcpa_failures == 0 && kem_failures == 0 {
                largest_zero_fail_bound = bound;
            }

        }

        assert!(largest_zero_fail_bound >= CANDIDATES[0]);
    }
}
