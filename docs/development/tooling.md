# Tooling

The pinned Rust toolchain requires the following components to be installed:

- rustfmt
- clippy

## Fehlersuche

| Fehlermeldung | Ursache | Lösung |
| --- | --- | --- |
| `error: component 'rustfmt' is not installed for toolchain` | Die benötigten Komponenten der fixierten Toolchain wurden noch nicht installiert. | Installiere die fehlenden Komponenten mit `rustup component add rustfmt clippy --toolchain <toolchain>` oder nutze `rustup component add rustfmt clippy --toolchain nightly`. |
| `error: toolchain 'nightly' is not installed` | Die Nightly-Toolchain ist lokal nicht vorhanden. | Installiere die Toolchain mit `rustup toolchain install nightly` oder passe die `rust-toolchain.toml`-Konfiguration an. |
| `error: The 'prover-stwo' feature requires the Rust nightly toolchain.` | Das Feature `prover-stwo` wurde aktiviert, aber der Build läuft nicht mit einer Nightly-Toolchain oder ohne `RUSTC_BOOTSTRAP`. | Wechsle auf eine Nightly-Toolchain (`rustup override set nightly`) oder setze vor dem Build `RUSTC_BOOTSTRAP=1`. |
