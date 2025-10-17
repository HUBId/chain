- [crates.io](https://crates.io/crates/malachite-q)
- [docs.rs](https://docs.rs/malachite-base/latest/malachite_q/)

Rather than using this crate directly, use the
[`malachite`](https://crates.io/crates/malachite) meta-crate. It re-exports all of this crate's
public members.

In `malachite-q`'s doctests you will frequently see import paths beginning with
`malachite_q::`. When using the `malachite` crate, replace this part of the paths with
`malachite::`.

The import path of the `Rational` type is shortened to `malachite::Rational`.

# malachite-q
This crate defines
[`Rational`](https://docs.rs/malachite-q/latest/malachite_q/struct.Rational.html)s. The name of
this crate refers to the mathematical symbol for rational numbers, ℚ.
- There are many functions defined on
  [`Rational`](https://docs.rs/malachite-q/latest/malachite_q/struct.Rational.html)s. These include
  - All the ones you'd expect, like addition, subtraction, multiplication, and division;
  - Functions related to conversion between
    [`Rational`](https://docs.rs/malachite-q/latest/malachite_q/struct.Rational.html)s and other
    kinds of numbers, including primitive floats;
  - Functions for Diophantine approximation;
  - Functions for expressing
    [`Rational`](https://docs.rs/malachite-q/latest/malachite_q/struct.Rational.html)s in
    scientific notation.
- The numerators and denominators of
  [`Rational`](https://docs.rs/malachite-q/latest/malachite_q/struct.Rational.html)s are stored as
  [`Natural`](https://docs.rs/malachite-nz/latest/malachite_nz/natural/struct.Natural.html)s, so
  [`Rational`](https://docs.rs/malachite-q/latest/malachite_q/struct.Rational.html)s with small
  numerators and denominators can be stored entirely on the stack.
- Most arithmetic involving
  [`Rational`](https://docs.rs/malachite-q/latest/malachite_q/struct.Rational.html)s requires
  (automatically) reducing the numerator and denominator. This is done very efficiently by using
  the high performance GCD and exact division algorithms implemented by
  [`Natural`](https://docs.rs/malachite-nz/latest/malachite_nz/natural/struct.Natural.html)s.

# Demos and benchmarks
This crate comes with a `bin` target that can be used for running demos and benchmarks.
- Almost all of the public functions in this crate have an associated demo. Running a demo
  shows you a function's behavior on a large number of inputs. For example, to demo
  [`Rational`](https://docs.rs/malachite-q/latest/malachite_q/struct.Rational.html) addition, you
  can use the following command:
  ```text
  cargo run --features bin_build --release -- -l 10000 -m exhaustive -d demo_rational_add
  ```
  This command uses the `exhaustive` mode, which generates every possible input, generally
  starting with the simplest input and progressing to more complex ones. Another mode is
  `random`. The `-l` flag specifies how many inputs should be generated.
- You can use a similar command to run benchmarks. The following command benchmarks various
  addition algorithms:
  ```text
  cargo run --features bin_build --release -- -l 1000000 -m random -b \
      benchmark_rational_add_algorithms -o gcd-bench.gp
  ```
  or GCD implementations of other libraries:
  ```text
  cargo run --features bin_build --release -- -l 1000000 -m random -b \
      benchmark_rational_add_assign_library_comparison -o gcd-bench.gp
  ```
  This creates a file called gcd-bench.gp. You can use gnuplot to create an SVG from it like
  so:
  ```text
  gnuplot -e "set terminal svg; l \"gcd-bench.gp\"" > gcd-bench.svg
  ```

The list of available demos and benchmarks is not documented anywhere; you must find them by
browsing through
[`bin_util/demo_and_bench`](https://github.com/mhogrefe/malachite/tree/master/malachite-q/src/bin_util/demo_and_bench).

# Features
- `32_bit_limbs`: Sets the type of `Limb` to
  [`u32`](https://doc.rust-lang.org/nightly/std/primitive.u32.html) instead of the default,
  [`u64`](https://doc.rust-lang.org/nightly/std/primitive.u64.html).
- `random`: This feature provides some functions for randomly generating values. It is off by
  default to avoid pulling in some extra dependencies.
- `enable_serde`: Enables serialization and deserialization using [serde](`https://serde.rs/`).
- `test_build`: A large proportion of the code in this crate is only used for testing. For a
  typical user, building this code would result in an unnecessarily long compilation time and
  an unnecessarily large binary. My solution is to only build this code when the `test_build`
  feature is enabled. If you want to run unit tests, you must enable `test_build`. However,
  doctests don't require it, since they only test the public interface. Enabling this feature also
  enables `random`.
- `bin_build`: This feature is used to build the code for demos and benchmarks, which also
  takes a long time to build. Enabling this feature also enables `test_build` and `random`.

Malachite is developed by Mikhail Hogrefe. Thanks to b4D8, florian1345, konstin, Rowan Hart, YunWon Jeong, Park Joon-Kyu, Antonio Mamić, OliverNChalk, shekohex, and skycloudd for additional contributions.

Copyright © 2025 Mikhail Hogrefe

## Vendor segment validation

To verify the vendored sources end-to-end, run [`scripts/vendor_malachite/test_segments.sh`](../../../scripts/vendor_malachite/test_segments.sh). The helper sequentially executes `download_segments.sh`, `merge_segments.sh`, and `verify_extracted_files.py` for every workspace crate:

```bash
./scripts/vendor_malachite/test_segments.sh
```

`malachite-q` writes its logs to [`logs/`](logs/):

- `download_segments_malachite_q_0_4_18.log`
- `merge_segments_malachite_q_0_4_18.log`
- `integrity_report.txt`

Um Binary-Diffs zu vermeiden, entfernt das Skript nach Abschluss automatisch
alle `.part*`-Segmente sowie das temporäre `.crate`. Falls du die Dateien
lokal behalten möchtest, setze `MALACHITE_KEEP_CHUNKS=1` vor dem Start.

Die Prüfberichte werden bewusst gekürzt, um Upload-Limits einzuhalten: pro Status (z. B. "missing in vendor") listet `integrity_report.txt` höchstens 50 Beispielpfade. Die vollständigen Zählwerte und Stichproben stehen im JSON-Gegenstück [`manifest/integrity_report.json`](manifest/integrity_report.json).
