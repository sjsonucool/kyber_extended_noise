# Uniform Error Distribution Modifications

## Summary

This document describes the modifications made to use a uniform distribution for the error scalar polynomial `epp` in the IND-CPA encryption layer, instead of the original centered binomial distribution.

## Changes Made

### 1. New Parameter: `KYBER_EPP_UNIFORM_BOUND`

**File**: `src/params.rs`

Added a new constant `KYBER_EPP_UNIFORM_BOUND` (default: 16) that defines the range `[-BOUND, BOUND)` from which `epp` coefficients are sampled uniformly.

```rust
pub const KYBER_EPP_UNIFORM_BOUND: i16 = 16;
```

### 2. New Function: `poly_getnoise_uniform`

**Files**: 
- `src/reference/poly.rs`
- `src/avx2/poly.rs`

Added a new function that samples polynomial coefficients uniformly from `[-KYBER_EPP_UNIFORM_BOUND, KYBER_EPP_UNIFORM_BOUND)` using rejection sampling.

### 3. Modified IND-CPA Encryption

**Files**:
- `src/reference/indcpa.rs`
- `src/avx2/indcpa.rs`

Changed `indcpa_enc()` to use `poly_getnoise_uniform()` for generating `epp` instead of `poly_getnoise_eta2()`.

### 4. Documentation for Q Adjustment

**File**: `src/params.rs`

Added comprehensive documentation explaining:
- The decryption correctness requirement: `|total_error| < Q/4`
- How to calculate if Q needs adjustment
- Examples for different uniform bounds

## Decryption Correctness

For correct decryption, the total error must satisfy: `|total_error| < Q/4`

### Error Sources:
1. **ep** (error vector): range `[-2, 2]` (eta2 distribution)
2. **epp** (error scalar): range `[-KYBER_EPP_UNIFORM_BOUND, KYBER_EPP_UNIFORM_BOUND)` (uniform)
3. **Compression error**: up to `Q/32` (4-bit compression) or `Q/64` (5-bit compression)

### Current Configuration:
- `KYBER_EPP_UNIFORM_BOUND = 16`
- `Q = 3329`
- Max error ≈ `2 + 16 + Q/32 ≈ 2 + 16 + 104 = 122 < Q/4 = 832` ✓

## Adjusting Q for Larger Uniform Bounds

If you want to use a larger uniform bound, you may need to increase Q:

### Example Calculations:

**For BOUND = 32:**
- Max error ≈ `2 + 32 + Q/32 ≈ 2 + 32 + 104 = 138`
- Required: `Q > 4 × 138 = 552`
- Suggested: `Q = 7681` (NTT-compatible)

**For BOUND = 64:**
- Max error ≈ `2 + 64 + Q/32 ≈ 2 + 64 + 104 = 170`
- Required: `Q > 4 × 170 = 680`
- Suggested: `Q = 7681` or `Q = 12289` (NTT-compatible)

### Important Notes:
- Q must be compatible with NTT (Number Theoretic Transform)
- Common NTT-compatible primes: `3329`, `7681`, `12289`
- Changing Q requires updating NTT constants and related arithmetic

## Usage

The modifications are active by default with `KYBER_EPP_UNIFORM_BOUND = 16`. To change the bound:

1. Edit `src/params.rs`:
   ```rust
   pub const KYBER_EPP_UNIFORM_BOUND: i16 = 32; // or your desired value
   ```

2. If using a larger bound, verify decryption correctness:
   - Check that `max_error < Q/4`
   - Adjust Q if necessary (requires NTT constant updates)

3. Rebuild the project:
   ```bash
   cargo build
   ```

## Testing

After modifications, verify:
1. **Compilation**: `cargo build`
2. **Unit tests**: `cargo test`
3. **Decryption correctness**: Test that encryption/decryption works correctly
4. **Known Answer Tests**: Run KATs if available

## Security Considerations

⚠️ **Warning**: Changing the error distribution may affect:
- Security proofs (if they depend on specific error distributions)
- Side-channel resistance
- Performance characteristics

Ensure that your modifications maintain the security properties required for your use case.
