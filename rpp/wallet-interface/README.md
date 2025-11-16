# rpp-wallet-interface

`rpp-wallet-interface` defines the serialization-friendly contracts that sit
between the wallet and the runtime.  The wallet is responsible for building and
submitting workflows (identity, transaction, uptime, etc.) but the runtime only
needs to understand a lightweight subset of the data.  Keeping those shared
structures in this crate lets us compile and test the interface layer without
pulling in the full wallet implementation while still documenting the exact
shape of the payloads that cross the boundary.

The crate intentionally keeps its dependency surface minimal: only `serde` for
encoding/decoding and `thiserror` for error reporting.  Downstream crates can
use these types to serialize payloads (e.g. to JSON over RPC) or validate the
shape of a workflow without linking against every wallet subsystem.
