# Compliance Test Targets

The following mandated tests document the minimum coverage the proving stack must
provide. Each test exercises a specific portion of the deterministic proving
pipeline and must remain green across all profiles.

| Test | Location | Coverage area |
| --- | --- | --- |
| `mandated_fft_roundtrip` | `src/fft/mod.rs` | Validates that the radix-2 FFT followed by the inverse transform restores the original trace, ensuring field arithmetic and twiddle scheduling stay deterministic. |
| `mandated_fft_root_selection_is_stable` | `src/fft/mod.rs` | Locks down primitive-root derivation so cached generator tables never drift between runs or binaries. |
| `mandated_ifft_roundtrip` | `src/fft/ifft.rs` | Confirms the inverse FFT in natural ordering perfectly inverts the forward transform, covering Montgomery conversions and scaling factors. |
| `mandated_lde_blowup_lengths` | `src/fft/lde.rs` | Checks low-degree extension blowup factors for the ×8 and ×16 profiles so domain sizing is deterministic. |
| `mandated_lde_deterministic_index_mapping` | `src/fft/lde.rs` | Ensures the row/column to evaluation-index mapping is bijective and profile-stable for both row-major and column-interleaved layouts. |
| `mandated_lde_worker_chunk_determinism` | `src/fft/lde.rs` | Verifies worker chunk schedulers cover the entire extended domain without overlap, guaranteeing reproducible multi-threaded execution. |

Implementations are expected to keep these tests, expand upon them as features
land, and use the documented coverage areas when triaging regressions.
