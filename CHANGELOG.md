# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [Unreleased]

### Added

- `PrefetchParserFactory` (`windows.prefetch`): prefetch files as pipeline records, one per
  recorded run time with `@timestamp` = that run, `process.name`, `file.path`,
  `prefetch.run_count`, `prefetch.run_index` and `prefetch.version`. It reads
  `C:\Windows\Prefetch`, or every `*.pf` found by name when that folder is absent (a triage
  collection). A file that can't be read is one `Err` item; a file's anomalies are carried on
  each of its records (`CHECKSUM_MISMATCH` for a CRC mismatch, every kind by name in
  `prefetch.anomalies`).
- `PrefetchAnomaly` and `PrefetchFile::anomalies`: a CRC mismatch, an executable name or path
  hash that differs from the file name, a file name with no hash, and a data file (`.NLS`,
  `.RES`) loaded with executable blocks are kept on the parsed file instead of being logged.
  Only `CrcMismatch` maps to a core `AnomalyFlags` bit (`CHECKSUM_MISMATCH`).
- `decompress::decompress_bounded`, which refuses output larger than the declared size.

### Fixed

- A MAM file with a bad CRC was rejected outright; it is now decompressed and parsed, with the
  mismatch kept as `CrcMismatch`. The compressed data of a CRC-flagged file (`MAM\x84`) also
  started 4 bytes early, at the CRC slot.
- The path hash in the file name (`CMD.EXE-087B4001.pf`) was parsed as decimal, so almost every
  file "mismatched"; it is hexadecimal. Names containing `-` are split at the last one.
- `read_prefetch_file_compressed` sliced its header without checking the length.
- LZNT1 runs through forensic-rs's panic-free `decompress_bounded`, bounded by the declared size,
  instead of behind `catch_unwind`; LZ77 and Xpress-Huffman keep the guard.
- `read_prefetch_form_fs` stops at no file that can't be opened (it aborted the whole batch), and
  opens the `read_dir` entry path directly now that `ChRootFileSystem` returns its own namespace.

## [0.14.0] - 27/08/2026

### Changed

- Migrate to forensic-rs 0.14: categorized `ForensicError` constructors (`invalid_format`, `other`, `file_size_error`, `no_more_data`), the `FileSystem`/`FileSystemExt` VFS trait rewrite (`read_prefetch_form_fs` now takes `&impl FileSystem` instead of `&mut impl VirtualFileSystem`), provenance-tracked `ForensicData` (`ForensicData::new` requires a minted `ProvenanceId`) and `ForensicResult`-wrapped items in `IntoTimeline`/`IntoActivity`.
- The removed `notifications` module (`notify_high!`/`notify_low!`/`notify_info!`) has no direct replacement outside a full triage pipeline; anomaly detection during parsing now goes through the existing `forensic_rs::warn!`/`info!` log macros instead.
- `decompress`: LZ77, Xpress-Huff, and LZNT1 decoding now all delegate to `forensic_rs::utils::win::decompress` instead of maintaining local implementations — this crate's own LZNT1 decoder was contributed upstream to forensic-rs (see its `CHANGELOG.md`) and this crate's copy removed once forensic-rs's version was verified and confirmed a drop-in match.
- `metrics_array_17` and the four `trace.rs` per-version trace-chain functions were hand-duplicating logic already generalized elsewhere in the module (mirroring the `stride`-parameterized pattern `volume.rs` already used); consolidated into shared stride/offset-parameterized helpers. No behavior change.
- `PREFETCH_SIZE_LIMIT` now has a doc comment explaining the threshold.

### Fixed

- `decompress`: the compression-algorithm dispatcher had `CompressionFormatLznt1` and `CompressionFormatXpress` swapped — `Lznt1` was routed to the plain-LZ77 decoder (with no real LZNT1 decoder wired in at all) and `Xpress` to the Huffman decoder. Fixed by wiring in this crate's own previously-unused LZNT1 decoder and routing `Xpress` to plain LZ77 (that decoder has since moved to forensic-rs, see above). Untested previously — no fixture in this repo exercises anything but Xpress-Huff — so added dispatcher-level regression tests, including one cross-checked against libyal/libfwnt's documented LZNT1 algorithm.
- `decompress`: `CompressionFormatNone` used `Vec::copy_from_slice`, which panics unless the output buffer already has the same length as the input; changed to `extend_from_slice`.
- Replaced 4 `unsafe { std::mem::transmute }` UTF-16 reinterpretation sites (in `process_prefetch_data` and the metrics parsers) with the existing safe `utf16_at_offset` helper, which itself no longer uses `transmute`.
- `process_prefetch_data` no longer panics on a prefetch buffer shorter than the fixed 84-byte header (previously indexed straight into the buffer); it now returns an `Err`.
- `u16_at_pos`/`u32_at_pos`/`u64_at_pos` no longer panic on an out-of-bounds `pos` — the previous `buffer[pos..pos+N].try_into().unwrap_or_default()` still panicked on the slice index before the fallback could run; they now use `buffer.get(..)`.
- Offset/count arithmetic in `metrics.rs`, `trace.rs`, and `volume.rs` (e.g. `offset + count * stride`) is now widened to `u64` (via a new shared `checked_range` helper) before bounds-checking, so a corrupted or adversarial offset/count pair can no longer overflow `u32`/`usize` and defeat the check.
- Removed a stray `println!` and dead commented-out code left over in `metrics.rs`/`prefetch.rs`.
- `utf16_at_offset` computed its `offset + size` bound as a plain `usize` addition (unlike the sibling `checked_range` helper, which deliberately widens to `u64`); a corrupted/adversarial `offset`/`size` pair read from a `.pf` file could overflow (panicking in debug builds) or wrap to a bogus small value that then panicked via an invalid slice range (release builds). Now widens to `u64` and bounds-checks before ever slicing, matching `checked_range`.
- `checked_range` cast its `u64`-widened bound back to `usize` with a bare `as`, which silently truncates on 32-bit targets and could reintroduce the overflow the widening was meant to prevent. Now uses `usize::try_from` and returns an error instead.
- A compressed prefetch file's `decompressed_size` header field (attacker/corruption-controlled) was passed straight to `Vec::with_capacity` with no upper bound, letting a small file declare a multi-gigabyte decompressed size and trigger a large-allocation attempt before the decompressor had verified anything. Now validated against a new `PREFETCH_DECOMPRESSED_SIZE_LIMIT` (64 MB) before allocating.
- `decompress()`'s LZNT1 and LZ77 (Xpress) code paths in forensic-rs can panic — rather than return an error — on truncated/malformed compressed input (`index out of bounds`, `range end index out of range`; caught by new regression tests in `decompress/mod.rs`). A single corrupted `.pf` file could previously abort an entire analysis run; `decompress()` now runs each foreign decoder behind `catch_unwind` and converts a panic into a `ForensicError`.
- `read_prefetch_form_fs` logged a per-file parse failure (e.g. a file dropped for exceeding `PREFETCH_SIZE_LIMIT`) at `info!` level, making a silently-skipped forensic artifact indistinguishable from routine noise. Raised to `warn!`.

### Added

- Unit tests for `common.rs`'s byte-reading/UTF-16 helpers, `PrefetchFlag`/`BlockFlags` formatting, and `PrefetchFile::executable_path`/`user`; unit tests in `metrics.rs`/`trace.rs`/`volume.rs` covering the new overflow/bounds-check behavior; negative-path tests in `tst.rs` (truncated header, bad signature, unknown version, corrupted huge offsets) driving the public `read_prefetch_file_no_compressed` entry point via `forensic_rs`'s `InMemoryVirtualFileSystem`.
- `cargo clippy` and `cargo fmt --check` now run in CI as a separate `lint` job.
- Unit tests closing coverage gaps identified in a later review pass: `metrics_array_26`/`_30`, `volume_info_23`/`_26`/`_30`, `extract_file_references_23`, `extract_directory_strings_23` (previously untested), plus malformed-input tests for `process_trace_chain_v30`/`traces_for_dependency_v30` and truncated/corrupted-input tests for the LZNT1/Xpress/Xpress-Huff decompression dispatch (the last of which caught the forensic-rs panic-on-truncated-input issue fixed above).

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