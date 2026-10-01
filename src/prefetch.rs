use std::io::Read;

use forensic_rs::{
    artifact::WindowsArtifacts,
    core::path::FPath,
    err::{ForensicError, ForensicResult},
    traits::vfs::{FileSystem, VFileType, VirtualFile},
    utils::time::Filetime,
};

use crate::{
    anomaly::PrefetchAnomaly,
    common::{u32_at_pos, u64_at_pos, utf16_at_offset, PrefetchFile, PrefetchFileInformation},
    decompress::{decompress_bounded, CompressionAlgorithm},
    metrics::*,
    volume::*,
};

/// Maximum accepted size, in bytes, for a prefetch file read off disk. An executable's `.pf` is
/// typically tens to a few hundred KB, but the boot trace (`NTOSBOOT-B00DFAAD.pf`) records every
/// file touched during boot: 1.8 and 2.4 MB on real Windows 7 machines, so a 1 MB cap refused it.
/// It bounds the memory one file can take, at the same 64 MB as the decompressed content.
const PREFETCH_SIZE_LIMIT: u64 = PREFETCH_DECOMPRESSED_SIZE_LIMIT;
/// Maximum accepted *decompressed* size declared in a compressed prefetch file's header. This is
/// checked before allocating the decompression output buffer: `decompressed_size` is an
/// attacker/corruption-controlled `u32` read from that header, so without this cap a tiny
/// compressed file could declare a multi-gigabyte decompressed size and trigger a
/// large-allocation attempt before the decompressor has verified anything. 64 MB is far beyond
/// any real prefetch file's decompressed size.
const PREFETCH_DECOMPRESSED_SIZE_LIMIT: u64 = 64_000_000;
/// Signature = MAM
// Predates this quality pass (forensic-rs 0.14 migration); left as an array literal rather
// than the clippy-suggested byte-string form to avoid touching unrelated migration code.
#[allow(clippy::byte_char_slices)]
const PREFETCH_COMPRESS_SIGNATURE: u32 = u32::from_le_bytes([b'M', b'A', b'M', b'\0']);
const PREFETC_COMPRESS_SIGNATURE_U8: &[u8] = b"MAM";

/// Reads all prefetch files on the folder C:\Windows\Prefetch.
///
/// A file that can't be opened or parsed is left out of the result and only logged.
///
/// ```rust
/// use forensic_rs::prelude::*;
/// use frnsc_prefetch::prelude::*;
/// use std::sync::Arc;
/// let fs = ChRootFileSystem::new("./artifacts/17/C", Arc::new(StdVirtualFS::new()));
/// let _list = read_prefetch_form_fs(&fs).expect("Must read all prefetch from filesystem");
/// ```
pub fn read_prefetch_form_fs(fs: &impl FileSystem) -> ForensicResult<Vec<PrefetchFile>> {
    forensic_rs::context::set_artifact(WindowsArtifacts::Prefetch);
    let prefetch_folder = FPath::new(r"C:\Windows\Prefetch");
    let prefetch_files = match fs.read_dir(prefetch_folder) {
        Ok(v) => v,
        Err(e) => {
            forensic_rs::warn!("No prefetch found");
            return Err(e);
        }
    };
    let mut prefetches = Vec::with_capacity(128);
    for entry in prefetch_files {
        let entry = entry?;
        if entry.file_type != VFileType::File {
            continue;
        }
        let file_name = match entry.file_name() {
            Some(v) => v.to_string(),
            None => continue,
        };
        if !file_name.ends_with(".pf") {
            continue;
        }
        let file = match fs.open(entry.path.as_path()) {
            Ok(file) => file,
            Err(e) => {
                forensic_rs::warn!("Cannot open prefetch {}: {}", file_name, e);
                continue;
            }
        };

        match read_prefetch_file(&file_name, file) {
            Ok(v) => {
                prefetches.push(v);
            }
            Err(e) => {
                // warn!, not info!: this drops a forensic artifact from the batch result
                // entirely (e.g. it exceeded PREFETCH_SIZE_LIMIT), which should be visible
                // under normal log-level filtering rather than only in verbose logs.
                forensic_rs::warn!("Error procesing prefetch {}: {}", file_name, e);
            }
        };
    }
    Ok(prefetches)
}

/// Parses a sinle prefetch file. The file name is supplied as to check the prefetch hash and the name.
///
/// ```rust
/// use forensic_rs::prelude::*;
/// use frnsc_prefetch::prelude::*;
/// use std::sync::Arc;
/// let fs = ChRootFileSystem::new("./artifacts/17/C", Arc::new(StdVirtualFS::new()));
/// let file = fs.open(FPath::new("C:\\Windows\\Prefetch\\CMD.EXE-087B4001.pf")).unwrap();
/// let _list = read_prefetch_file("CMD.EXE-087B4001.pf", file).expect("Must read all prefetch from filesystem");
/// ```
pub fn read_prefetch_file(
    artifact_name: &str,
    mut file: Box<dyn VirtualFile>,
) -> ForensicResult<PrefetchFile> {
    let mut buffer = [0u8; 64];
    file.read_exact(&mut buffer)?;
    if file_is_compressed(&buffer) {
        read_prefetch_file_compressed(artifact_name, file)
    } else {
        read_prefetch_file_no_compressed(artifact_name, file)
    }
}

fn file_is_compressed(buffer: &[u8]) -> bool {
    PREFETC_COMPRESS_SIGNATURE_U8 == &buffer[0..3]
}

/// Parsers a prefetch file that is compressed.
///
/// ```rust
/// use forensic_rs::prelude::*;
/// use frnsc_prefetch::prelude::*;
/// let fs = StdVirtualFS::new();
/// let file = fs.open(FPath::new("./artifacts/30/C/Windows/Prefetch/RUST_OUT.EXE-5D2C8541.pf")).unwrap();
/// read_prefetch_file_compressed("RUST_OUT.EXE-5D2C8541.pf", file).unwrap();
/// ```
pub fn read_prefetch_file_compressed(
    artifact_name: &str,
    mut file: Box<dyn VirtualFile>,
) -> ForensicResult<PrefetchFile> {
    file.seek(std::io::SeekFrom::Start(0))?;
    let file_size = file.metadata()?.size;
    if file_size > PREFETCH_SIZE_LIMIT {
        return Err(ForensicError::file_size_error(
            "prefetch_file",
            PREFETCH_SIZE_LIMIT,
            file_size,
        ));
    }
    let mut buffer = Vec::with_capacity(4096);
    file.read_to_end(&mut buffer)?;
    // An 8-byte header, then at least the CRC slot of the compressed data.
    if buffer.len() < 12 {
        return Err(ForensicError::buffer_too_small(
            12,
            buffer.len(),
            "compressed prefetch header",
        ));
    }
    let header = &buffer[0..8];
    let compressed = &buffer[8..];
    let signature = u32_at_pos(header, 0);
    let decompressed_size = u32_at_pos(header, 4);
    let compress_algorithm: CompressionAlgorithm = ((signature & 0x0F000000) >> 24).into();
    let crc_ck = (signature & 0xF0000000) >> 28;
    let magic = signature & 0x00FFFFFF;
    if magic != PREFETCH_COMPRESS_SIGNATURE {
        return Err(ForensicError::invalid_format(
            "prefetch",
            format!("Invalid prefetch signature: {}", magic),
        ));
    }
    // A CRC mismatch is evidence about the file, not a reason to refuse it: the content is still
    // decompressed and parsed (a damaged payload then fails there), and the mismatch is kept.
    let mut crc_anomaly = None;
    if crc_ck > 0 {
        let stored = u32_at_pos(compressed, 0);
        let mut hash = crc32fast::Hasher::new();
        hash.update(header);
        hash.update(&[0, 0, 0, 0]);
        hash.update(&compressed[4..]);
        let computed = hash.finalize();
        if computed != stored {
            crc_anomaly = Some(PrefetchAnomaly::CrcMismatch { stored, computed });
        }
    }
    if u64::from(decompressed_size) > PREFETCH_DECOMPRESSED_SIZE_LIMIT {
        return Err(ForensicError::file_size_error(
            "prefetch_file_decompressed",
            PREFETCH_DECOMPRESSED_SIZE_LIMIT,
            u64::from(decompressed_size),
        ));
    }
    // With a CRC, the compressed data starts after its 4-byte slot.
    let payload = if crc_ck > 0 {
        &compressed[4..]
    } else {
        compressed
    };
    let mut decompressed = Vec::with_capacity(decompressed_size as usize);
    decompress_bounded(
        payload,
        &mut decompressed,
        compress_algorithm,
        decompressed_size as usize,
    )?;
    let mut prefetch = process_prefetch_data(artifact_name, &decompressed)?;
    prefetch.anomalies.extend(crc_anomaly);
    Ok(prefetch)
}

/// Parsers a prefetch file that is not compressed.
///
/// ```rust
/// use forensic_rs::prelude::*;
/// use frnsc_prefetch::prelude::*;
/// let fs = StdVirtualFS::new();
/// let file = fs.open(FPath::new("./artifacts/23/C/Windows/Prefetch/NOTEPAD.EXE-D8414F97.pf")).unwrap();
/// read_prefetch_file_no_compressed("NOTEPAD.EXE-D8414F97.pf", file).unwrap();
/// ```
pub fn read_prefetch_file_no_compressed(
    artifact_name: &str,
    mut file: Box<dyn VirtualFile>,
) -> ForensicResult<PrefetchFile> {
    file.seek(std::io::SeekFrom::Start(0))?;
    let file_size = file.metadata()?.size;
    if file_size > PREFETCH_SIZE_LIMIT {
        return Err(ForensicError::file_size_error(
            "prefetch_file",
            PREFETCH_SIZE_LIMIT,
            file_size,
        ));
    }
    let mut buffer = Vec::with_capacity(4096);
    file.read_to_end(&mut buffer)?;
    process_prefetch_data(artifact_name, &buffer)
}

fn process_prefetch_data(artifact_name: &str, buffer: &[u8]) -> ForensicResult<PrefetchFile> {
    if buffer.len() < 84 {
        return Err(ForensicError::buffer_too_small(
            84,
            buffer.len(),
            "prefetch header",
        ));
    }
    let version = u32_at_pos(buffer, 0);
    let signature = &buffer[4..8];
    if b"SCCA" != signature {
        return Err(ForensicError::invalid_format(
            "prefetch",
            "Invalid prefetch signature",
        ));
    }
    let executable_name = utf16_at_offset(buffer, 16, 60)?;
    let raw_hash = u32_at_pos(buffer, 76);
    let anomalies = check_prefetch_info_correct(artifact_name, &executable_name, raw_hash);

    let mut prefetch_content = PrefetchFile {
        name: executable_name,
        version,
        anomalies,
        ..Default::default()
    };
    if version == 17 {
        let info = file_information_17(&buffer[84..])?;
        prefetch_content.metrics = metrics_array_17(buffer, &info)?;
        prefetch_content.volume = volume_info_17(buffer, &info)?;
        prefetch_content.last_run_times = info.last_run_times;
        prefetch_content.run_count = info.run_count;
    } else if version == 23 {
        let info = file_information_23(&buffer[84..])?;
        prefetch_content.metrics = metrics_array_23(buffer, &info)?;
        prefetch_content.volume = volume_info_23(buffer, &info)?;
        prefetch_content.last_run_times = info.last_run_times;
        prefetch_content.run_count = info.run_count;
    } else if version == 26 {
        let info = file_information_26(&buffer[84..])?;
        prefetch_content.metrics = metrics_array_26(buffer, &info)?;
        prefetch_content.volume = volume_info_26(buffer, &info)?;
        prefetch_content.last_run_times = info.last_run_times;
        prefetch_content.run_count = info.run_count;
    } else if version == 30 || version == 31 {
        let info = file_information_30(&buffer[84..])?;
        prefetch_content.metrics = metrics_array_30(buffer, &info)?;
        prefetch_content.volume = volume_info_30(buffer, &info)?;
        prefetch_content.last_run_times = info.last_run_times;
        prefetch_content.run_count = info.run_count;
    } else {
        return Err(ForensicError::invalid_format(
            "prefetch",
            format!("The prefetch version is unknown: {}", version),
        ));
    };
    for metric in &prefetch_content.metrics {
        if data_file_with_executable_blocks(metric) {
            prefetch_content
                .anomalies
                .push(PrefetchAnomaly::ExecutableBlockInDataFile {
                    file: metric.file.clone(),
                });
        }
    }
    Ok(prefetch_content)
}

/// v17 header (oldest supported format, Windows XP): the fixed-header field offsets used here
/// are the baseline that later versions extend/shift. `buffer` is the prefetch file starting at
/// offset 84 (right after the name/hash fields read in [`process_prefetch_data`]).
fn file_information_17(buffer: &[u8]) -> ForensicResult<PrefetchFileInformation> {
    Ok(PrefetchFileInformation {
        metrics_offsets: u32_at_pos(buffer, 0),
        metrics_count: u32_at_pos(buffer, 4),
        trace_chain_offset: u32_at_pos(buffer, 8),
        trace_chain_count: u32_at_pos(buffer, 12),
        filename_string_offset: u32_at_pos(buffer, 16),
        filename_string_size: u32_at_pos(buffer, 20),
        volume_information_offset: u32_at_pos(buffer, 24),
        volume_count: u32_at_pos(buffer, 28),
        volume_information_size: u32_at_pos(buffer, 32),
        last_run_times: vec![Filetime::new(u64_at_pos(buffer, 36))],
        run_count: u32_at_pos(buffer, 60),
    })
}

/// v23 header: same field order as v17 but `last_run_times`/`run_count` shift further into the
/// header (offsets 44/68 vs v17's 36/60) — later Windows versions grew the fixed header.
fn file_information_23(buffer: &[u8]) -> ForensicResult<PrefetchFileInformation> {
    Ok(PrefetchFileInformation {
        metrics_offsets: u32_at_pos(buffer, 0),
        metrics_count: u32_at_pos(buffer, 4),
        trace_chain_offset: u32_at_pos(buffer, 8),
        trace_chain_count: u32_at_pos(buffer, 12),
        filename_string_offset: u32_at_pos(buffer, 16),
        filename_string_size: u32_at_pos(buffer, 20),
        volume_information_offset: u32_at_pos(buffer, 24),
        volume_count: u32_at_pos(buffer, 28),
        volume_information_size: u32_at_pos(buffer, 32),
        last_run_times: vec![Filetime::new(u64_at_pos(buffer, 44))],
        run_count: u32_at_pos(buffer, 68),
    })
}

/// v26 header: instead of a single `last_run_times` entry, up to 8 non-zero `Filetime`s are
/// read from offsets 44..108 (8-byte stride); `run_count` moves to offset 124.
fn file_information_26(buffer: &[u8]) -> ForensicResult<PrefetchFileInformation> {
    let mut last_run_times = Vec::with_capacity(8);
    for i in (44..108).step_by(8) {
        let run_time = u64_at_pos(buffer, i);
        if run_time == 0 {
            continue;
        }
        last_run_times.push(Filetime::new(run_time));
    }
    Ok(PrefetchFileInformation {
        metrics_offsets: u32_at_pos(buffer, 0),
        metrics_count: u32_at_pos(buffer, 4),
        trace_chain_offset: u32_at_pos(buffer, 8),
        trace_chain_count: u32_at_pos(buffer, 12),
        filename_string_offset: u32_at_pos(buffer, 16),
        filename_string_size: u32_at_pos(buffer, 20),
        volume_information_offset: u32_at_pos(buffer, 24),
        volume_count: u32_at_pos(buffer, 28),
        volume_information_size: u32_at_pos(buffer, 32),
        last_run_times,
        run_count: u32_at_pos(buffer, 124),
    })
}

/// v30 header, variant 1 (`metrics_offsets == 304`): same field layout as v26 (`run_count` at
/// offset 124). See [`file_information_30`] for how the variant is detected.
fn file_information_30v1(buffer: &[u8]) -> ForensicResult<PrefetchFileInformation> {
    let mut last_run_times = Vec::with_capacity(8);
    for i in (44..108).step_by(8) {
        let run_time = u64_at_pos(buffer, i);
        if run_time == 0 {
            continue;
        }
        last_run_times.push(Filetime::new(run_time));
    }
    Ok(PrefetchFileInformation {
        metrics_offsets: u32_at_pos(buffer, 0),
        metrics_count: u32_at_pos(buffer, 4),
        trace_chain_offset: u32_at_pos(buffer, 8),
        trace_chain_count: u32_at_pos(buffer, 12),
        filename_string_offset: u32_at_pos(buffer, 16),
        filename_string_size: u32_at_pos(buffer, 20),
        volume_information_offset: u32_at_pos(buffer, 24),
        volume_count: u32_at_pos(buffer, 28),
        volume_information_size: u32_at_pos(buffer, 32),
        last_run_times,
        run_count: u32_at_pos(buffer, 124),
    })
}

/// v30 header, variant 2 (default when `metrics_offsets != 304`): identical to variant 1 except
/// `run_count` sits at offset 116 instead of 124.
fn file_information_30v2(buffer: &[u8]) -> ForensicResult<PrefetchFileInformation> {
    let mut last_run_times = Vec::with_capacity(8);
    for i in (44..108).step_by(8) {
        let run_time = u64_at_pos(buffer, i);
        if run_time == 0 {
            continue;
        }
        last_run_times.push(Filetime::new(run_time));
    }
    Ok(PrefetchFileInformation {
        metrics_offsets: u32_at_pos(buffer, 0),
        metrics_count: u32_at_pos(buffer, 4),
        trace_chain_offset: u32_at_pos(buffer, 8),
        trace_chain_count: u32_at_pos(buffer, 12),
        filename_string_offset: u32_at_pos(buffer, 16),
        filename_string_size: u32_at_pos(buffer, 20),
        volume_information_offset: u32_at_pos(buffer, 24),
        volume_count: u32_at_pos(buffer, 28),
        volume_information_size: u32_at_pos(buffer, 32),
        last_run_times,
        run_count: u32_at_pos(buffer, 116),
    })
}

/// Dispatches to the v30 header variant based on `metrics_offsets`, the only field whose value
/// reliably distinguishes the two on-disk layouts (see [`file_information_30v1`]/[`file_information_30v2`]).
/// Versions 30 and 31 share this same header format.
fn file_information_30(buffer: &[u8]) -> ForensicResult<PrefetchFileInformation> {
    let metrics_offsets = u32_at_pos(buffer, 0);
    if metrics_offsets == 304 {
        return file_information_30v1(buffer);
    }
    file_information_30v2(buffer)
}

/// Compares the executable name and path hash stored in the file with the ones in its file name
/// (`<EXE>-<HASH>.pf`). Only checked for a `.pf` name.
fn check_prefetch_info_correct(
    artifact_name: &str,
    executable_name: &str,
    hash: u32,
) -> Vec<PrefetchAnomaly> {
    let mut anomalies = Vec::new();
    if !artifact_name.to_ascii_lowercase().ends_with(".pf") {
        return anomalies;
    }
    match extract_hash_and_name(artifact_name) {
        Some((expected_name, expected_hash)) => {
            // Both names are the same truncated upper-case form; compare without regard to case
            // so a tool that lower-cased the file name doesn't look like a rename.
            if !expected_name.eq_ignore_ascii_case(executable_name) {
                anomalies.push(PrefetchAnomaly::NameMismatch {
                    file_name: expected_name.to_string(),
                    embedded: executable_name.to_string(),
                });
            }
            if hash != expected_hash {
                anomalies.push(PrefetchAnomaly::HashMismatch {
                    file_name: expected_hash,
                    embedded: hash,
                });
            }
        }
        None => anomalies.push(PrefetchAnomaly::NoHashInName {
            file_name: artifact_name.to_string(),
        }),
    }
    anomalies
}

/// `CMD.EXE-087B4001.pf` -> `("CMD.EXE", 0x087B4001)`. The hash is hexadecimal and follows the
/// last `-`, since executable names can contain dashes themselves.
fn extract_hash_and_name(name: &str) -> Option<(&str, u32)> {
    let stem = name.get(..name.len().checked_sub(3)?)?;
    let (exe, hash) = stem.rsplit_once('-')?;
    let hash = u32::from_str_radix(hash, 16).ok()?;
    Some((exe, hash))
}
