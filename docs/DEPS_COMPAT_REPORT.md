# Abhängigkeits-Kompatibilitätsbericht

| Crate | Edition | Deklarierte MSRV | Aktivierte Features (Workspace) | Maßnahme |
| --- | --- | --- | --- | --- |
| `base64ct` | 2021 | 1.60 | keine (Default-Features deaktiviert) | Explizit auf `=1.6.0` fixiert, um die Edition-2024-Anforderung von `1.8.0` zu vermeiden. Beobachten, bis eine Edition-2021-konforme 1.x-Version verfügbar ist. |
| `malachite` | 2021 | 1.74 | `enable_serde`, `serde` | Auf `=0.4.18` zurückgesetzt; diese Version deklariert Rust 1.74/Edition 2021, während Veröffentlichungen ab `0.5.x` Rust ≥1.83 und Edition 2024 voraussetzen. Kompilation auf Rust 1.79 scheitert weiter an `char::MIN` (Upstream nutzt noch Nightly-Feature) – Workaround/Fork nötig, sobald verfügbar. |
| `prover_stwo_backend` (`stwo`) | 2021 | 1.79 | Feature `prover-stwo` (aktiviert die vendored `official`-Implementierung) | Keine Aktion – Pfadabhängigkeit bleibt auf interner Edition 2021. |
| `stwo-official` | 2021 | — | `std` (Default-Feature über `prover-stwo`) | Keine Aktion – vendored Quelle bereits Edition 2021; MSRV nicht angegeben. |
| `storage-firewood` | 2021 | 1.79 | — | Keine Aktion erforderlich. |
| `rpp-stark` | 2021 | 1.79 | optionale Auditing-/Parallel-Features ungenutzt | Keine Aktion erforderlich. |
| `libp2p` | 2021 | 1.75 | `gossipsub`, `identify`, `macros`, `ping`, `plaintext`, `tokio`, `yamux` | Auf `=0.54.1` fixiert und transitive `ed25519-dalek`-Version via Lockfile auf `2.1.1` gehalten (MSRV 1.60), um das 1.81-Upgrade zu vermeiden. |
| `reqwest` | 2021 | 1.63 | `json`, `rustls-tls` | Auf `=0.11.27` zurückgesetzt, damit `url`/`idna` nicht auf ICU-basierte 1.82-Abhängigkeiten hochgezogen werden. |
| `url` | 2021 | 1.56 | — | Neu als Direktabhängigkeit auf `=2.4.1` fixiert, um `idna@0.4.0` (ohne ICU) zu erzwingen. |
| `tokio` | 2021 | 1.70 | `macros`, `rt-multi-thread`, `signal`, `sync`, `time`, `net` | Keine Aktion – erfüllt Rust 1.79. |
| `ed25519-dalek` | 2018 | — | `serde` | Keine Aktion – Edition ≤2021 und keine Nightly-Features. |

## Folgeaktionen

* `base64ct`: Auf `=1.6.0` fixiert. Upstream-Version `1.8.0` erfordert Edition 2024/Rust 1.85; erneut evaluieren, sobald eine Edition-2021-kompatible Veröffentlichung erscheint.
* `malachite`: Auf `=0.4.18` fixiert. Versionen ab `0.5.0` verlangen Edition 2024/Rust ≥1.83; darüber hinaus blockiert `char::MIN` weiterhin die Kompilierung auf Rust 1.79 → kurzfristig Fork/Patch einplanen.
* `libp2p`: Auf `=0.54.1` fixiert und `ed25519-dalek` transitive auf `2.1.1` gehalten; nach Upstream-Fix für MSRV ≥1.81 erneut bewerten.
* `reqwest`/`url`: Auf `=0.11.27` bzw. `=2.4.1` fixiert, um ICU-basierte `idna`-Abhängigkeiten zu vermeiden. Abwarten, bis die `idna`-1.x-Kette Edition 2021 ohne ICU anbietet.
