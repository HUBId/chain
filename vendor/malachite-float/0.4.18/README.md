- [crates.io](https://crates.io/crates/malachite-float)
- [docs.rs](https://docs.rs/malachite-base/latest/malachite_float/)

Rather than using this crate directly, use the
[`malachite`](https://crates.io/crates/malachite) meta-crate. It re-exports all of this crate's
public members.

In `malachite-float`'s doctests you will frequently see import paths beginning with
`malachite_float::`. When using the `malachite` crate, replace this part of the paths with
`malachite::`.

The import path of the `Float` type is shortened to `malachite::Float`.

# malachite-float
This crate defines
[`Float`](https://docs.rs/malachite-float/latest/malachite_float/struct.Float.html)s.

TODO

Malachite is developed by Mikhail Hogrefe. Thanks to b4D8, florian1345, konstin, Rowan Hart, YunWon Jeong, Park Joon-Kyu, Antonio Mamić, OliverNChalk, shekohex, and skycloudd for additional contributions.

Copyright © 2025 Mikhail Hogrefe

## Vendor segment validation

[`scripts/vendor_malachite/test_segments.sh`](../../../scripts/vendor_malachite/test_segments.sh) triggers the full pipeline (`download_segments.sh` → `merge_segments.sh` → `verify_extracted_files.py`) for all Malachite crates:

```bash
./scripts/vendor_malachite/test_segments.sh
```

`malachite-float` records its logs under [`logs/`](logs/):

- `download_segments_malachite_float_0_4_18.log`
- `merge_segments_malachite_float_0_4_18.log`
- `integrity_report.txt`

Nach dem Lauf löscht das Skript automatisch alle heruntergeladenen `.part*`
Segmente sowie das temporär erzeugte `.crate`, um Binärdateien aus dem
Repository fernzuhalten. Mit `MALACHITE_KEEP_CHUNKS=1` lassen sich die
Artefakte bei Bedarf lokal behalten.

Die Prüfberichte werden bewusst gekürzt, um Upload-Limits einzuhalten: pro Status (z. B. "missing in vendor") listet `integrity_report.txt` höchstens 50 Beispielpfade. Die vollständigen Zählwerte und Stichproben stehen im JSON-Gegenstück [`manifest/integrity_report.json`](manifest/integrity_report.json).
