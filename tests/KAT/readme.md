# Known Answer Tests (Legacy)

The legacy `kyber_kat` flow in this repository is intentionally disabled.

Reason:
- This codebase now targets a fixed custom parameter set, not upstream Kyber 512/768/1024.
- The upstream KAT files (`tvecs512/768/1024`) are no longer applicable.

Current behavior:
- Enabling `RUSTFLAGS='--cfg kyber_kat'` fails fast with a compile-time error.

If custom-parameter KAT support is needed later, it should be reintroduced with:
- a custom vector-generation pipeline,
- a fixed filename/schema convention for this parameter set,
- and updated loader/test logic.
