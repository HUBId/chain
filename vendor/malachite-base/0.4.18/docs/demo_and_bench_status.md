# `bin_util` demo and bench import status

## Imported in this update
- `generate/` code generation helpers (max base, run-length encoding, tuning manager)
- Demo & bench modules for:
  - `bools`
  - `chars`
  - `comparison`
  - `rounding_modes`
  - `slices`
  - `strings`

## Outstanding numeric demo modules
The remaining `num` demo modules are still pending import. The upstream crate exposes the
following numeric categories that must be integrated before the CLI reaches feature parity:

- `num/arithmetic` (comprehensive arithmetic demos & benches)
- `num/comparison`
- `num/conversion`
- `num/factorization`
- `num/float`
- `num/logic`

These modules depend on large numeric stacks (e.g. big integer traits and advanced
algorithms). Bringing them in requires additional supporting crates and code, so they will be
handled in follow-up work.
