// Copyright 2018 Parity Technologies (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

#![allow(unused_doc_comments)]

//! Rust-libp2p Tutorials to get started with.
//!
//! The upstream crate ships runnable tutorial binaries under
//! `libp2p/src/tutorials`, but the vendored copy that chain depends on does
//! not include those heavy example sources.  The module tree still exists so
//! documentation links and references remain valid, but we provide inline
//! placeholder modules rather than referencing missing files to keep `cargo
//! fmt` and other tooling happy.

#[cfg(doc)]
pub mod hole_punching {
    //! Placeholder module that keeps the documentation hierarchy intact while
    //! trimming the vendored dependency size.
    //!
    //! The full tutorial is available in the upstream libp2p repository:
    //! <https://github.com/libp2p/rust-libp2p/tree/master/src/tutorials>.
}

#[cfg(doc)]
pub mod ping {
    //! Placeholder module mirroring the upstream ping tutorial.
    //!
    //! This module intentionally omits executable code in this fork; consult
    //! upstream documentation for runnable examples.
}
