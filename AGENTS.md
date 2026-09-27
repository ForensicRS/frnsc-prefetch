# AGENTS.md

## What this crate is

`frnsc-prefetch` is a pure-Rust parser for Windows Prefetch (`.pf`) files, versions 17/23/26/30/31 (XP through Windows 10/11). It's a VFS-driven parser built on `forensic-rs`'s filesystem abstraction, not a live-system-only tool — it reads through any `forensic_rs::traits::vfs::FileSystem` (a real disk, a `ChRootFileSystem` over extracted artifacts, a mounted image, etc.), so it works on all platforms, not just Windows.

Module layout, one concern per file under `src/`:
- `prefetch.rs` — entry points (`read_prefetch_form_fs`, `read_prefetch_file*`) and per-version header/field-offset parsing.
- `common.rs` — shared structs (`PrefetchFile`, `Metric`, `Trace`, `VolumeInformation`, ...), byte-reading helpers, and the `IntoTimeline`/`IntoActivity` trait impls that turn a parsed `PrefetchFile` into forensic-rs's `TimelineData`/`ForensicActivity`.
- `metrics.rs`, `trace.rs`, `volume.rs` — the metrics array, trace chain, and volume-information sub-parsers, one function per prefetch version.
- `anomaly.rs` — `PrefetchAnomaly`: what a file's structure or file name contradicts (CRC, name, hash, executable blocks in a data file), kept on `PrefetchFile::anomalies`.
- `decompress/` — dispatches to the compression algorithm a prefetch file's MAM header declares. All three algorithms (LZ77, LZ77+Huffman/Xpress-Huff, and LZNT1) delegate to `forensic_rs::utils::win::decompress`; this crate has no algorithm implementations of its own anymore, only `decompress/mod.rs`'s `CompressionAlgorithm` dispatch (re-exported from forensic-rs) and its regression tests.

## Build / test

- `cargo build` / `cargo check` — cross-platform, no `cfg(windows)` gating (CI runs `cargo test --verbose` on ubuntu/windows/macos, see `.github/workflows/rust.yml`).
- `cargo test` — parses real fixture `.pf` files under `./artifacts/<version>/C/Windows/Prefetch/...` (checked into the repo). Most tests open a fixture directly via `StdVirtualFS`; `should_parse_all_prefetchs_from_fs` and the `#[ignore]`d `should_parse_current_prefetches` exercise `read_prefetch_form_fs` instead (see the `ChRootFileSystem` note below). `tests/case_facts.rs` checks real CTF prefetch files against the forensic-testenv case `unizar-bolas-cocido` (skipped unless fetched).
- `cargo test --doc` — the doctests on `prefetch.rs`'s public functions are the other concrete usage examples; keep them and `README.md`'s code blocks in sync with the real API when either changes.

## Dependency on forensic-rs

- This crate's own `version` in `Cargo.toml` tracks the **minor version** of the `forensic-rs` it targets (e.g. this crate at `0.14.0` targets `forensic-rs` `0.14.x`). Keep them in lockstep when bumping either.
- `forensic-rs` lives in a sibling checkout at `../forensic-rs` and is developed in tandem with this crate; the local (gitignored) `.cargo/config.toml` patches `forensic-rs` to that path for development builds.
- If forensic-rs's VFS (`traits::vfs::FileSystem`), error (`err::ForensicError`), or data-model (`data::ForensicData`, `traits::forensic::IntoTimeline`/`IntoActivity`) surfaces change in a future version, check its `CHANGELOG.md` for the exact breaking-change list before touching this crate's imports — read the actual `../forensic-rs/src` for the new signatures rather than assuming the changelog prose alone is precise enough to port from.
- Don't assume forensic-rs's own code is correct just because it exists — its `utils::win::decompress::{lz77, xpress_huff}` were originally lifted verbatim from this crate, bugs included (its `CompressionAlgorithm` dispatcher had `Lznt1`/`Xpress` swapped and no real LZNT1 decoder at all). Both bugs have since been fixed upstream in forensic-rs too (an `lznt1` module was contributed there, ported from this crate's own decoder and independently verified against libyal/libfwnt's documented LZNT1 algorithm — see forensic-rs's `CHANGELOG.md`), so `decompress/mod.rs` here now delegates all three algorithms straight through with no local override. If forensic-rs's dispatcher ever regresses, this crate's own `decompress::tests::dispatches_*` tests (in `decompress/mod.rs`) will catch it, since they drive the fix through `decompress()` itself rather than trusting the algorithm functions individually.

## `ChRootFileSystem` note

- `ChRootFileSystem`'s root **represents the drive itself**: a drive designator (`C:`) in a queried path is dropped, not honored. So a chroot meant to emulate `C:\` needs its root pointed *at* the drive-letter folder (e.g. `ChRootFileSystem::new("./artifacts/17/C", ...)`), not one level above it — see `should_parse_all_prefetchs_from_fs` in `src/tst.rs`. (`read_dir` entries are in the chroot's own namespace since forensic-rs `a78e366`, so `entry.path` can be opened directly.)

## Conventions

- `ForensicError` construction goes through the categorized constructors (`ForensicError::invalid_format(artifact_type, reason)`, `::other(category, message)`, `::file_size_error(operation, max, actual)`, `::no_more_data()`) — `bad_format_str`/`bad_format_string` still compile but are deprecated, avoid reintroducing them.
- Anything the analyst should see is data, not a log line: a contradiction in the file is a `PrefetchAnomaly` on `PrefetchFile::anomalies` (only `CrcMismatch` maps to a core `AnomalyFlags` bit; the others are recorded by name), and a file the parser can't go on with is an `Err`. Log macros are for engineers debugging the crate.
- Update `CHANGELOG.md` with a version-numbered entry for behavior/API changes, matching the terse Keep-a-Changelog style already there.
