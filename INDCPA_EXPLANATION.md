# IND-CPA Encryption in Kyber: How It Works (With Uniform Error Distribution)

## Overview: What is IND-CPA?

**IND-CPA** (Indistinguishability under Chosen Plaintext Attack) is a security property that means:
- An attacker cannot distinguish between encryptions of different messages
- Even if they can choose which messages to encrypt and see the ciphertexts
- The encryption must be probabilistic (randomized) to achieve this

Kyber uses a **lattice-based** encryption scheme where security comes from the Learning With Errors (LWE) problem.

---

## Kyber's IND-CPA Encryption Scheme

### Mathematical Structure

Kyber encrypts a message `m` (32 bytes) using:
- **Public key**: `pk = (A, t)` where:
  - `A` is a `k×k` matrix of polynomials (deterministically generated from seed)
  - `t = A·s + e` (where `s` is secret key, `e` is error from key generation)

- **Encryption**:
  ```
  b = A^T·sp + ep    (vector of k polynomials)
  v = t^T·sp + epp + m'  (single polynomial)
  ```
  Where:
  - `sp` = secret polynomial vector (random, small)
  - `ep` = error polynomial vector (random, small)
  - `epp` = error scalar polynomial (random, small) ← **THIS IS WHAT WE CHANGED**
  - `m'` = message encoded as polynomial

- **Decryption**:
  ```
  mp = s^T·b - v
    = s^T·(A^T·sp + ep) - (t^T·sp + epp + m')
    = s^T·A^T·sp + s^T·ep - A·s·sp - e·sp - epp - m'
    = (s^T·A^T - A·s)·sp + s^T·ep - e·sp - epp - m'
    = s^T·ep - e·sp - epp - m'
  ```
  
  Since `s^T·ep - e·sp - epp` is small (error terms), we can recover `m'` by rounding.

---

## Original Error Distributions

### Before Our Changes

All error polynomials used **Centered Binomial Distribution (CBD)**:

1. **`sp`** (secret vector): CBD with `η₁` parameter
   - Kyber-512: η₁ = 3 → coefficients in range [-3, 3]
   - Kyber-768/1024: η₁ = 2 → coefficients in range [-2, 2]

2. **`ep`** (error vector): CBD with `η₂ = 2`
   - Coefficients in range [-2, 2]

3. **`epp`** (error scalar): CBD with `η₂ = 2`
   - Coefficients in range [-2, 2] ← **ORIGINAL**

### Centered Binomial Distribution

For η=2, CBD works by:
- Taking 2 random bits per coefficient
- Computing `a - b` where `a, b ∈ {0,1,2}`
- Result: values in `{-2, -1, 0, 1, 2}` with probabilities `{1/16, 4/16, 6/16, 4/16, 1/16}`

This creates a "bell curve" distribution centered at 0.

---

## What Changed: Uniform Distribution for `epp`

### The Modification

We changed **only** the `epp` error polynomial to use a **uniform distribution** instead of CBD:

```rust
// OLD (centered binomial):
poly_getnoise_eta2(&mut epp, coins, nonce);

// NEW (uniform):
poly_getnoise_uniform(&mut epp, coins, nonce);
```

### Uniform Distribution Details

**Range**: `[-KYBER_EPP_UNIFORM_BOUND, KYBER_EPP_UNIFORM_BOUND)`
- Default: `KYBER_EPP_UNIFORM_BOUND = 16`
- Coefficients uniformly distributed in `[-16, -15, ..., 15]` (32 possible values)
- Each value has probability `1/32`

**Implementation** (rejection sampling):
1. Generate random bytes via PRF (Pseudo-Random Function)
2. Extract values in range `[0, 2*BOUND)`
3. Reject values ≥ `2*BOUND` (to get uniform distribution)
4. Shift: `coefficient = value - BOUND` → range `[-BOUND, BOUND)`

### Why Uniform?

- **Larger error range**: Can use larger errors (16 vs 2) while maintaining correctness
- **Different security properties**: Uniform distribution may have different security characteristics
- **Research/testing**: Allows experimentation with different error distributions

---

## How IND-CPA Encryption Works Now

### Step-by-Step Process

#### 1. **Setup** (`indcpa_enc`)

```rust
// Input: message m (32 bytes), public key pk, random coins (32 bytes)
unpack_pk(&mut pkpv, &mut seed, pk);  // Extract A and seed from pk
poly_frommsg(&mut k, m);              // Encode message as polynomial
gen_at(&mut at, &seed);              // Generate matrix A^T
```

#### 2. **Generate Random Polynomials**

All randomness comes from the `coins` seed (deterministic):

```rust
// Secret vector (small, used once)
for i in 0..KYBER_K {
    poly_getnoise_eta1(&mut sp.vec[i], coins, nonce);  // CBD, η₁
    nonce += 1;
}

// Error vector (small, added to b)
for i in 0..KYBER_K {
    poly_getnoise_eta2(&mut ep.vec[i], coins, nonce);   // CBD, η₂
    nonce += 1;
}

// Error scalar (small, added to v) ← CHANGED
poly_getnoise_uniform(&mut epp, coins, nonce);          // UNIFORM, bound=16
```

**Key point**: Each polynomial uses a unique `nonce` to ensure independence.

#### 3. **Compute Ciphertext in NTT Domain**

```rust
polyvec_ntt(&mut sp);  // Convert sp to NTT domain (for fast multiplication)

// Matrix-vector multiplication: b = A^T·sp
for i in 0..KYBER_K {
    polyvec_basemul_acc_montgomery(&mut b.vec[i], &at[i], &sp);
}

// Dot product: v = t^T·sp
polyvec_basemul_acc_montgomery(&mut v, &pkpv, &sp);
```

**NTT (Number Theoretic Transform)**: Like FFT but for modular arithmetic. Enables fast polynomial multiplication.

#### 4. **Convert Back and Add Errors**

```rust
polyvec_invntt_tomont(&mut b);  // Convert b back from NTT
poly_invntt_tomont(&mut v);     // Convert v back from NTT

// Add error polynomials
polyvec_add(&mut b, &ep);       // b = A^T·sp + ep
poly_add(&mut v, &epp);         // v = t^T·sp + epp
poly_add(&mut v, &k);           // v = t^T·sp + epp + m'
```

#### 5. **Compress and Pack**

```rust
polyvec_reduce(&mut b);  // Reduce coefficients mod Q
poly_reduce(&mut v);     // Reduce coefficients mod Q
pack_ciphertext(c, &mut b, v);  // Compress and serialize
```

**Compression**: Quantizes coefficients to save space:
- `b`: 4-bit compression (128 bytes for 256 coefficients)
- `v`: 4-bit compression (128 bytes) or 5-bit (160 bytes for Kyber-1024)

---

## Decryption Process

### Step-by-Step

#### 1. **Unpack Ciphertext**

```rust
unpack_ciphertext(&mut b, &mut v, c);  // Decompress b and v
unpack_sk(&mut skpv, sk);              // Extract secret key s
```

#### 2. **Compute Message Polynomial**

```rust
polyvec_ntt(&mut b);                              // Convert b to NTT
polyvec_basemul_acc_montgomery(&mut mp, &skpv, &b);  // mp = s^T·b
poly_invntt_tomont(&mut mp);                      // Convert back
poly_sub(&mut mp, &v);                            // mp = s^T·b - v
poly_reduce(&mut mp);                             // Reduce mod Q
```

**Mathematically**:
```
mp = s^T·b - v
   = s^T·(A^T·sp + ep) - (t^T·sp + epp + m')
   = s^T·A^T·sp + s^T·ep - A·s·sp - e·sp - epp - m'
   = s^T·ep - e·sp - epp - m'
```

#### 3. **Recover Message**

```rust
poly_tomsg(m, mp);  // Decode polynomial back to message
```

**How it works**:
- Message encoding: bit `0` → coefficient `0`, bit `1` → coefficient `(Q+1)/2 = 1665`
- Decoding: Check if coefficient is closer to `0` or `1665`
- Formula: `bit = ((2*coeff + Q/2) / Q) & 1`

---

## Decryption Correctness

### Why It Works

For correct decryption, the **total error** must be small enough:

```
Total Error = s^T·ep - e·sp - epp - compression_error
```

**Requirement**: `|total_error| < Q/4 = 832.5` (for Q=3329)

### Error Bounds

With our changes:

1. **`s^T·ep`**: 
   - `s` has coefficients in `[-η₁, η₁]` (typically [-2, 2])
   - `ep` has coefficients in `[-2, 2]`
   - Max contribution: `k × 2 × 2 = 12` (for k=3, Kyber-768)

2. **`e·sp`**:
   - Similar bound: `k × 2 × 2 = 12`

3. **`epp`** (CHANGED):
   - **Old**: coefficients in `[-2, 2]` → max `2`
   - **New**: coefficients in `[-16, 15]` → max `16`
   - **Increase**: 8× larger error per coefficient

4. **Compression error**:
   - 4-bit compression: quantization error up to `Q/32 ≈ 104`
   - 5-bit compression: quantization error up to `Q/64 ≈ 52`

### Total Error Calculation

**With uniform epp (bound=16)**:
```
Max error ≈ 12 + 12 + 16 + 104 = 144 < 832.5 ✓
```

**Safety margin**: We have `832.5 - 144 = 688.5` of headroom.

### What If We Increase the Bound?

For `KYBER_EPP_UNIFORM_BOUND = 32`:
```
Max error ≈ 12 + 12 + 32 + 104 = 160 < 832.5 ✓
```

For `KYBER_EPP_UNIFORM_BOUND = 64`:
```
Max error ≈ 12 + 12 + 64 + 104 = 192 < 832.5 ✓
```

For `KYBER_EPP_UNIFORM_BOUND = 200`:
```
Max error ≈ 12 + 12 + 200 + 104 = 328 < 832.5 ✓
```

**We could go up to ~700 before needing to increase Q!**

---

## Security Implications

### Why Errors Are Necessary

Errors (`ep`, `epp`) are **essential** for security:

1. **Without errors**: The scheme would be deterministic and insecure
2. **With small errors**: Creates the LWE problem (hard to solve)
3. **Error distribution matters**: Affects security proofs and side-channel resistance

### Uniform vs Centered Binomial

**Centered Binomial (original)**:
- Values cluster around 0 (bell curve)
- Smaller variance
- Used in security proofs

**Uniform (our change)**:
- All values equally likely
- Larger variance (for same bound)
- May require new security analysis

### Important Note

⚠️ **Changing the error distribution may affect**:
- Security proofs (if they assume CBD)
- Side-channel resistance
- Performance

**Recommendation**: Use this modification for research/testing. For production, verify security properties.

---

## Summary of Changes

### What We Modified

1. **Added parameter**: `KYBER_EPP_UNIFORM_BOUND = 16` in `params.rs`
2. **New function**: `poly_getnoise_uniform()` in both reference and AVX2 implementations
3. **Changed encryption**: `indcpa_enc()` now uses uniform distribution for `epp`
4. **Documentation**: Added comments and guide for Q adjustment

### What Stayed the Same

- `sp` still uses CBD with η₁
- `ep` still uses CBD with η₂
- Encryption/decryption algorithm unchanged
- All other parameters unchanged

### Impact

- **Correctness**: Maintained (errors still small enough)
- **Security**: May need re-analysis (different error distribution)
- **Performance**: Similar (rejection sampling has small overhead)
- **Flexibility**: Can now easily adjust uniform bound

---

## Code Flow Diagram

```
IND-CPA Encryption:
┌─────────────────────────────────────────┐
│ Input: m (message), pk (public key),     │
│        coins (random seed)               │
└──────────────┬──────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────┐
│ 1. Generate random polynomials:          │
│    - sp (CBD, η₁)                       │
│    - ep (CBD, η₂)                       │
│    - epp (UNIFORM, bound=16) ← CHANGED  │
└──────────────┬──────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────┐
│ 2. Compute in NTT domain:               │
│    b = A^T·sp                            │
│    v = t^T·sp                            │
└──────────────┬──────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────┐
│ 3. Convert back, add errors:             │
│    b = A^T·sp + ep                       │
│    v = t^T·sp + epp + m'                │
└──────────────┬──────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────┐
│ 4. Compress and pack:                    │
│    c = pack(b, v)                        │
└──────────────────────────────────────────┘

IND-CPA Decryption:
┌──────────────────────────────────────────┐
│ Input: c (ciphertext), sk (secret key)   │
└──────────────┬──────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────┐
│ 1. Unpack and compute:                  │
│    mp = s^T·b - v                       │
│      = s^T·ep - e·sp - epp - m'        │
└──────────────┬──────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────┐
│ 2. Recover message:                     │
│    m = decode(mp)  (rounding)           │
└──────────────────────────────────────────┘
```

---

This modification allows you to experiment with larger uniform error distributions while maintaining decryption correctness, as long as the total error stays below `Q/4`.
