# Wallet GUI third-party inventory

The `wallet_gui` feature enables iced-based desktop binaries built from the
`rpp-wallet` crate. This document captures the key third-party crates that ship
with those builds so compliance reviews do not have to re-derive the dependency
list from scratch.

## Core UI stack

| Crate | Version | License | Notes |
| --- | --- | --- | --- |
| `iced` | 0.12.1 | MIT | MVU UI toolkit used by `rpp-wallet-gui` to render tabs, dialogs, and clipboard guards.【F:docs/wallet-deps/wallet_gui.txt†L1-L40】【74aa88†L2-L2】 |
| `iced_wgpu` | 0.12.1 | MIT | GPU renderer that maps iced widgets onto `wgpu` surfaces.【F:docs/wallet-deps/wallet_gui.txt†L1-L80】【74aa88†L3-L3】 |
| `iced_winit` | 0.12.2 | MIT | Desktop windowing/event loop integration for iced.【F:docs/wallet-deps/wallet_gui.txt†L1-L40】【74aa88†L3-L3】 |
| `wgpu` | 0.19.4 | MIT OR Apache-2.0 | Cross-platform graphics backend leveraged by `iced_wgpu`.【F:docs/wallet-deps/wallet_gui.txt†L1-L80】【74aa88†L4-L4】 |
| `winit` | 0.29.15 | Apache-2.0 | Window/event loop library used via `iced_winit` to drive OS integrations.【F:docs/wallet-deps/wallet_gui.txt†L1-L40】【74aa88†L6-L6】 |

## Clipboard and QR helpers

| Crate | Version | License | Notes |
| --- | --- | --- | --- |
| `arboard` | 3.6.1 | MIT OR Apache-2.0 | Clipboard abstraction used for the GUI copy/paste flows described in the Phase 3 guide.【F:docs/wallet-deps/wallet_gui.txt†L1-L40】【74aa88†L1-L1】 |
| `qrcode` | 0.13.0 | MIT OR Apache-2.0 | Encodes receive addresses and backup fingerprints into QR codes for the GUI and CLI receipts.【F:docs/wallet-deps/wallet_gui.txt†L1-L80】【74aa88†L5-L5】 |

The complete dependency tree (including transitive crates) lives in
`docs/wallet-deps/wallet_gui.txt`. Regenerate that file whenever `cargo tree`
changes so this inventory stays accurate.
