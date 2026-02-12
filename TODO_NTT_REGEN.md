# Regenerating q-dependent precomputations (k=12, q=13_835_058_055_275_898_369)

We can keep AVX2 disabled for now and focus on restoring the reference NTT/Montgomery path. Steps:

1) Choose primitive 256th root of unity (omega)
   - Find g in Z_q^* such that omega = g^((q-1)/256) has exact order 256.
   - Verify omega^256 ≡ 1 mod q and omega^(128) ≠ 1.

2) Montgomery / reduction constants
   - Pick R = 2^32 (or 2^64). Compute:
     - QINV = −q^{-1} mod R (for montgomery_reduce)
     - Barrett constant v = floor(2^k / q) for chosen k (e.g., 26 or 52 bits depending on reducer design)
   - Decide reducer width (32- or 64-bit) and adjust types accordingly.

3) Twiddle tables
   - Build tmp[0] = R mod q; tmp[i] = mont_reduce(tmp[i-1] * (R * omega mod q)) for i=1..127.
   - ZETAS[i] = tmp[tree[i]] using the Kyber tree permutation (see `src/reference/ntt.rs` comments).
   - Center to (−q/2, q/2] if keeping signed representation.
   - Compute inverse twiddles/scaling: invZETAS (reverse order) and final F = R^2 / N mod q for invNTT.

4) Update reference code
   - Restore `src/reference/reduce.rs` with new QINV/Barrett v and reducer matching chosen width.
   - Replace ZETAS/F in `src/reference/ntt.rs`; re-enable ntt()/invntt()/montgomery_reduce path.
   - Switch `poly_basemul`, `poly_ntt`, `poly_invntt_tomont`, `poly_reduce`, `poly_tomont` back to NTT/Montgomery versions using new constants.

5) (Optional later) AVX2 regeneration
   - If re-enabling AVX2: rebuild `_ZETAS_EXP` and Montgomery constants in `src/avx2/consts.rs/.h` and refresh ntt.S/invntt.S/basemul.S tables.

6) Verify
   - Unit checks: forward NTT + inverse NTT returns input; basemul matches schoolbook mod q.
   - Run `cargo test --tests kem` and large encrypt/decrypt stress.

Notes:
- Current `epp` bound is 16; with a correct NTT path you can revisit larger bounds once total error is reevaluated.
- Keep AVX2 feature disabled until its tables are regenerated.

