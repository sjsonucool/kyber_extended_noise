# Testing

Without any feature flags `cargo test` will run through the key exchange functions and doctests for the fixed custom parameter set.

Legacy standard-Kyber KAT mode (`RUSTFLAGS='--cfg kyber_kat'`) is disabled in this repository because the parameter set has diverged from upstream Kyber 512/768/1024 vectors.
Attempting to enable `kyber_kat` now fails fast with a clear compile-time error.

For applicible x86 architectures you must export the avx2 RUSTFLAGS if you don't want to test on the reference codebase.

To run a matrix of supported features/modes use the helper script from this folder:
```shell
./run_all_tests.sh
```

The script also checks for the existence of different environment variables and modifies
its behaviour

* KAT: Enables legacy KAT cfg (expected to fail fast in this custom-parameter repo)
* AVX2: Runs avx2 code on x86 platforms with compiled GAS files
* NASM: Runs avx2 code with both GAS and NASM files seperately, requires a NASM compiler installed

To activate, instantiate the variables, for example:

```shell
KAT=1 AVX2=1 NASM=1 ./run_all_tests.sh 
```

Test files:

* [kat.rs](./kat.rs)  - Fail-fast guard for unsupported legacy `kyber_kat` mode.

* [kex.rs](./kex.rs) - Goes through a full key exchange procedure for both the UAKE and AKE functions.

* [kem.rs](./kem.rs) - A single run of random key generation, encapsulation and decapsulation.
