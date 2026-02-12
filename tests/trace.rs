use pqc_kyber::{decapsulate, encapsulate, keypair, reference, KyberError};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::time::Instant;

fn to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
}

#[test]
fn trace_indcpa_and_kem() -> Result<(), KyberError> {
    //let mut rng = StdRng::seed_from_u64(1234);
    let mut rng = rand::thread_rng(); 

    // INDCPA path
    let mut pk = vec![0u8; pqc_kyber::params::KYBER_INDCPA_PUBLICKEYBYTES];
    let mut sk = vec![0u8; pqc_kyber::params::KYBER_INDCPA_SECRETKEYBYTES];
    let t0 = Instant::now();
    reference::indcpa::indcpa_keypair(&mut pk, &mut sk, None, &mut rng)?;
    let kp_time = t0.elapsed();

    let mut m = [0u8; pqc_kyber::params::KYBER_SYMBYTES];
    rng.fill_bytes(&mut m);
    let mut coins = [0u8; pqc_kyber::params::KYBER_SYMBYTES];
    rng.fill_bytes(&mut coins);
    let mut c = vec![0u8; pqc_kyber::params::KYBER_INDCPA_BYTES];
    let t1 = Instant::now();
    reference::indcpa::indcpa_enc(&mut c, &m, &pk, &coins);
    let enc_time = t1.elapsed();
    let t2 = Instant::now();
    let mut m_dec = [0u8; pqc_kyber::params::KYBER_SYMBYTES];
    reference::indcpa::indcpa_dec(&mut m_dec, &c, &sk);
    let dec_time = t2.elapsed();

    println!("INDCPA m     : {}", to_hex(&m));
    println!("INDCPA m_dec : {}", to_hex(&m_dec));
    println!("INDCPA ct len: {} bytes", c.len());
    let indcpa_total = kp_time + enc_time + dec_time;
    println!(
        "INDCPA times : keypair={:?} enc={:?} dec={:?} total={:?}",
        kp_time, enc_time, dec_time, indcpa_total
    );

    // KEM path
    let t3 = Instant::now();
    let kp = keypair(&mut rng)?;
    let pk_kem = kp.public;
    let sk_kem = kp.secret;
    let kem_kp = t3.elapsed();
    let t4 = Instant::now();
    let (ct_kem, ss1) = encapsulate(&pk_kem, &mut rng)?;
    let kem_enc = t4.elapsed();
    let t5 = Instant::now();
    let ss2 = decapsulate(&ct_kem, &sk_kem)?;
    let kem_dec = t5.elapsed();

    println!("KEM ss_enc : {}", to_hex(&ss1));
    println!("KEM ss_dec : {}", to_hex(&ss2));
    println!("KEM ct len : {} bytes", ct_kem.len());
    let kem_total = kem_kp + kem_enc + kem_dec;
    println!(
        "KEM times  : keypair={:?} encap={:?} decap={:?} total={:?}",
        kem_kp, kem_enc, kem_dec, kem_total
    );

    assert_eq!(m, m_dec, "INDCPA decrypt mismatch");
    assert_eq!(ss1, ss2, "KEM shared secret mismatch");
    Ok(())
}
