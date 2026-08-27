# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [0.14.0] - 27/08/2026

### Changed

- Migrate to forensic-rs 0.14: categorized `ForensicError` constructors (`invalid_format`, `other`, `file_size_error`, `no_more_data`), the `FileSystem`/`FileSystemExt` VFS trait rewrite (`read_prefetch_form_fs` now takes `&impl FileSystem` instead of `&mut impl VirtualFileSystem`), provenance-tracked `ForensicData` (`ForensicData::new` requires a minted `ProvenanceId`) and `ForensicResult`-wrapped items in `IntoTimeline`/`IntoActivity`.
- The removed `notifications` module (`notify_high!`/`notify_low!`/`notify_info!`) has no direct replacement outside a full triage pipeline; anomaly detection during parsing now goes through the existing `forensic_rs::warn!`/`info!` log macros instead.
- `decompress`: LZ77, Xpress-Huff, and LZNT1 decoding now all delegate to `forensic_rs::utils::win::decompress` instead of maintaining local implementations — this crate's own LZNT1 decoder was contributed upstream to forensic-rs (see its `CHANGELOG.md`) and this crate's copy removed once forensic-rs's version was verified and confirmed a drop-in match.

### Fixed

- `decompress`: the compression-algorithm dispatcher had `CompressionFormatLznt1` and `CompressionFormatXpress` swapped — `Lznt1` was routed to the plain-LZ77 decoder (with no real LZNT1 decoder wired in at all) and `Xpress` to the Huffman decoder. Fixed by wiring in this crate's own previously-unused LZNT1 decoder and routing `Xpress` to plain LZ77 (that decoder has since moved to forensic-rs, see above). Untested previously — no fixture in this repo exercises anything but Xpress-Huff — so added dispatcher-level regression tests, including one cross-checked against libyal/libfwnt's documented LZNT1 algorithm.
- `decompress`: `CompressionFormatNone` used `Vec::copy_from_slice`, which panics unless the output buffer already has the same length as the input; changed to `extend_from_slice`.
- Replaced 4 `unsafe { std::mem::transmute }` UTF-16 reinterpretation sites (in `process_prefetch_data` and the metrics parsers) with the existing safe `utf16_at_offset` helper, which itself no longer uses `transmute`.
- `process_prefetch_data` no longer panics on a prefetch buffer shorter than the fixed 84-byte header (previously indexed straight into the buffer); it now returns an `Err`.
- `u16_at_pos`/`u32_at_pos`/`u64_at_pos` no longer panic on an out-of-bounds `pos` — the previous `buffer[pos..pos+N].try_into().unwrap_or_default()` still panicked on the slice index before the fallback could run; they now use `buffer.get(..)`.
- Offset/count arithmetic in `metrics.rs`, `trace.rs`, and `volume.rs` (e.g. `offset + count * stride`) is now widened to `u64` (via a new shared `checked_range` helper) before bounds-checking, so a corrupted or adversarial offset/count pair can no longer overflow `u32`/`usize` and defeat the check.
- Removed a stray `println!` and dead commented-out code left over in `metrics.rs`/`prefetch.rs`.

### Added

- Unit tests for `common.rs`'s byte-reading/UTF-16 helpers, `PrefetchFlag`/`BlockFlags` formatting, and `PrefetchFile::executable_path`/`user`; unit tests in `metrics.rs`/`trace.rs`/`volume.rs` covering the new overflow/bounds-check behavior; negative-path tests in `tst.rs` (truncated header, bad signature, unknown version, corrupted huge offsets) driving the public `read_prefetch_file_no_compressed` entry point via `forensic_rs`'s `InMemoryVirtualFileSystem`.
- `cargo clippy` and `cargo fmt --check` now run in CI as a separate `lint` job.

## [0.13.3] - 18/02/2025 

### Added

- Support for Prefetch version 31

## [0.13.2] - 21/10/2024 

### Fixed

- Correctly parse the MFT entry number

## [0.13.1] - 23/09/2024 

### Fixed

- Suporrt rust version 1.81

## [0.13.0] - 23/09/2024 

### Added

- Sync version of ForensicRS version 0.13