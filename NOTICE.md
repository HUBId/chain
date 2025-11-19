# NOTICE

This product bundles the following third-party components. Review their licenses
before redistributing compiled wallet artifacts.

- **iced 0.12.1 (MIT)** – Core GUI framework that powers the Phase 3 MVU wallet
  interface. The dependency tree is captured in `docs/wallet-deps/wallet_gui.txt`
  and the crate publishes an MIT license via cargo metadata.【F:docs/wallet-deps/wallet_gui.txt†L1-L40】【74aa88†L2-L2】
- **iced_wgpu 0.12.1 (MIT) & wgpu 0.19.4 (MIT OR Apache-2.0)** – GPU renderer and
  graphics backend used by the GUI builds. They ship under permissive dual
  licenses per cargo metadata and appear alongside the iced dependency listing.【F:docs/wallet-deps/wallet_gui.txt†L1-L80】【74aa88†L3-L6】
- **iced_winit 0.12.2 (MIT) & winit 0.29.15 (Apache-2.0)** – Window/event loop
  layer for desktop shells. These crates are required for GUI binaries on
  Linux/macOS/Windows.【F:docs/wallet-deps/wallet_gui.txt†L1-L40】【74aa88†L3-L7】
- **arboard 3.6.1 (MIT OR Apache-2.0)** – Cross-platform clipboard helper used by
  GUI clipboard guards. The dependency is recorded in the wallet GUI tree and
  inherits a dual MIT/Apache license per cargo metadata.【F:docs/wallet-deps/wallet_gui.txt†L1-L40】【74aa88†L1-L1】
- **qrcode 0.13.0 (MIT OR Apache-2.0)** – QR encoder for receive flows and backup
  validation. Listed in the GUI dependency manifest and licensed under MIT/Apache
  via cargo metadata.【F:docs/wallet-deps/wallet_gui.txt†L1-L80】【74aa88†L5-L5】

Third-party provenance for the Plonky3 backend remains documented separately in
`docs/third_party/plonky3.md`.
