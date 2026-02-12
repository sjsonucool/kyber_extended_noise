# Kyber (custom N=256, k=12, large q) – Change Summary & Next Steps

## Parameter & Feature Changes
- Set k=12, q=13_835_058_055_275_898_369 (u128). No compression; coeffs serialized as 8-byte LE words.
- `KYBER_EPP_UNIFORM_BOUND` currently 16 (conservative) to keep total error well below q/4 with unchanged CBD(η=2) secrets/errors.
- AVX2 path disabled; only reference path builds.

## Type & Serialization
- `Poly.coeffs` widened to `i128`.
- Polynomial/vector (de)serialization rewritten to full-width u64 per coeff (no bit-packing).
- Message encode/decode updated for the widened modulus.

## Arithmetic Pipeline
- NTT/Montgomery path removed from active code; NTT functions are no-ops.
- `poly_basemul`: schoolbook negacyclic convolution with per-term mod-q reduction (no twiddles).
- `poly_reduce`: simple mod-q; `poly_tomont` is a no-op.
- `poly_sub`: corrected to in-place r -= a semantics used by callers.

## Noise Sampling & Matrix Gen
- Uniform sampler for `epp` uses 64-bit modulus reduction; CBD samplers output `i128`.
- Matrix generation now SHAKE output reduced mod q (no 12-bit rejection tied to q=3329).

## Disabled/Bypassed q=3329 Precomputations
- Old `ZETAS`, Barrett/Montgomery constants, and AVX2 `QDATA` tables are not used; AVX2 feature stubbed.

## Current Bottleneck
- Arithmetic is pure schoolbook (O(N^2)), so performance is low.
- Correctness depends on avoiding residual sign/order mismatches; tests pass with small `epp`, but larger `epp` or AVX2 would require regenerated q-specific constants and a full NTT path.

## Plan to Restore Performance / Larger epp
1) Regenerate q-dependent constants for the new modulus:
   - Twiddle table (ZETAS) and inverse/scale factors for NTT/invNTT.
   - Montgomery `QINV`, Barrett constants; rebuild `reduce` helpers.
   - If re-enabling AVX2: regenerate `consts`/`QDATA` and assembly tables with new twiddles.
2) Reintroduce NTT/Montgomery pipeline (reference first, then AVX2), update `basemul`/`polyvec` ops accordingly.
3) Re-evaluate `epp` bound against total noise (CBD η=2 or adjusted); empirically test failure rate.
4) Restore optional AVX2 feature once constants are in place; benchmark.

