use clap::Parser;

/// Minimal CLI entry point for the `rpp-chain` crate.
///
/// This binary exists to make it easy to explore the crate with `cargo run`.
#[derive(Parser, Debug)]
#[command(author, version, about = "Command-line interface for rpp-chain tooling", long_about = None)]
struct ChainCli;

fn main() {
    ChainCli::parse();
}
