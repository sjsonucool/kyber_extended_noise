#![cfg(kyber_kat)]

compile_error!(
    "Legacy kyber_kat mode is not supported for this fixed custom parameter set. \
Use the standard test suite without --cfg kyber_kat."
);
