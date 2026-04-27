/// Module dimension k.
///
/// For the custom parameter set derived with lattice_estimator we fix
/// k = 12 (independent of feature flags).
pub const KYBER_K: usize = 12;

/// A boolean flag for whether 90's mode is activated.
///
/// If true AES-CTR and SHA2 will be used as cryptographic primitives instead,
/// which may have hardware speed-ups on certain platforms.
///
/// Defaults to false, set`features = ["90s"]` in Cargo.toml to enable.
pub const KYBER_90S: bool = cfg!(feature = "90s");

pub const KYBER_N: usize = 256;

/// Modulus Q for polynomial arithmetic (64‑bit prime picked by lattice_estimator).
pub const KYBER_Q: u128 = 13_835_058_055_275_898_369u128;

/// Noise parameters are left at the classic Kyber defaults.
pub const KYBER_ETA1: usize = 2;
pub const KYBER_ETA2: usize = 2;

/// Uniform error distribution bound for epp (error scalar polynomial).
/// Scalar error bound (uniform). Conservative value to maintain correctness.
pub const KYBER_EPP_UNIFORM_BOUND: i128 = 3458764513818968448;

// Size of the hashes and seeds
pub const KYBER_SYMBYTES: usize = 32;

/// Size of the shared key
pub const KYBER_SSBYTES: usize = 32;

/// Each coefficient is stored as an uncompressed little‑endian u64.
pub const KYBER_POLYBYTES: usize = KYBER_N * 8;
pub const KYBER_POLYVECBYTES: usize = KYBER_K * KYBER_POLYBYTES;

/// No compression for wide modulus; keep sizes equal to full representation.
pub const KYBER_POLYCOMPRESSEDBYTES: usize = KYBER_POLYBYTES;
pub const KYBER_POLYVECCOMPRESSEDBYTES: usize = KYBER_POLYVECBYTES;

pub const KYBER_INDCPA_PUBLICKEYBYTES: usize = KYBER_POLYVECBYTES + KYBER_SYMBYTES;
pub const KYBER_INDCPA_SECRETKEYBYTES: usize = KYBER_POLYVECBYTES;
pub const KYBER_INDCPA_BYTES: usize = KYBER_POLYVECCOMPRESSEDBYTES + KYBER_POLYCOMPRESSEDBYTES;

/// Size in bytes of the Kyber public key
pub const KYBER_PUBLICKEYBYTES: usize = KYBER_INDCPA_PUBLICKEYBYTES;
/// Size in bytes of the Kyber secret key
pub const KYBER_SECRETKEYBYTES: usize =
    KYBER_INDCPA_SECRETKEYBYTES + KYBER_INDCPA_PUBLICKEYBYTES + 2 * KYBER_SYMBYTES;
/// Size in bytes of the Kyber ciphertext
pub const KYBER_CIPHERTEXTBYTES: usize = KYBER_INDCPA_BYTES;
