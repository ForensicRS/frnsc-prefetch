use std::io::Read;

use forensic_rs::{
    artifact::WindowsArtifacts,
    core::path::FPath,
    err::{ForensicError, ForensicResult},
    traits::vfs::{FileSystem, VFileType, VirtualFile},
    utils::time::Filetime,
};

use crate::{
    common::{u32_at_pos, u64_at_pos, utf16_at_offset, PrefetchFile, PrefetchFileInformation},
    decompress::{decompress, CompressionAlgorithm},
    metrics::*,
    volume::*,
};

const PREFETCH_SIZE_LIMIT: u64 = 1_000_000;
/// Signature = MAM
// Predates this quality pass (forensic-rs 0.14 migration); left as an array literal rather
// than the clippy-suggested byte-string form to avoid touching unrelated migration code.
#[allow(clippy::byte_char_slices)]
const PREFETCH_COMPRESS_SIGNATURE: u32 = u32::from_le_bytes([b'M', b'A', b'M', b'\0']);
const PREFETC_COMPRESS_SIGNATURE_U8: &[u8] = b"MAM";

/// Reads all prefetch files on the folder C:\Windows\Prefetch.
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
        // Don't reuse `entry.path`: some `FileSystem` implementations (e.g.
        // `ChRootFileSystem`) return an already-resolved path from `read_dir`
        // that isn't valid input for a second `open()` call on the same `fs`.
        let file = fs.open(prefetch_folder.join(&file_name).as_path())?;

        match read_prefetch_file(&file_name, file) {
            Ok(v) => {
                prefetches.push(v);
            }
            Err(e) => {
                forensic_rs::info!("Error procesing prefetch {}: {}", file_name, e);
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
        forensic_rs::warn!("File size is abnormally large");
        return Err(ForensicError::file_size_error(
            "prefetch_file",
            PREFETCH_SIZE_LIMIT,
            file_size,
        ));
    }
    let mut buffer = Vec::with_capacity(4096);
    file.read_to_end(&mut buffer)?;
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
    if crc_ck > 0 {
        let file_crc = u32_at_pos(compressed, 0);
        let mut hash = crc32fast::Hasher::new();
        hash.update(header);
        hash.update(&[0, 0, 0, 0]);
        hash.update(&compressed[4..]);
        let crc32 = hash.finalize();
        if crc32 != file_crc {
            forensic_rs::warn!(
                "Invalid CRC for prefetch {:?}: expected={} obtained={}",
                artifact_name,
                file_crc,
                crc32
            );
            return Err(ForensicError::invalid_format(
                "prefetch",
                "The CRC of the prefetch does not match",
            ));
        }
    }
    let mut decompressed = Vec::with_capacity(decompressed_size as usize);
    decompress(compressed, &mut decompressed, compress_algorithm)?;
    process_prefetch_data(artifact_name, &decompressed)
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
        forensic_rs::warn!("Prefetch file {} size is abnormally large", artifact_name);
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
    check_prefetch_info_correct(artifact_name, &executable_name, raw_hash);

    let mut prefetch_content = PrefetchFile {
        name: executable_name,
        version,
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
        forensic_rs::warn!("The prefetch version is unknown: {}", version);
        return Err(ForensicError::invalid_format(
            "prefetch",
            format!("The prefetch version is unknown: {}", version),
        ));
    };
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

fn check_prefetch_info_correct(artifact_name: &str, executable_name: &str, hash: u32) {
    if artifact_name.ends_with(".pf") {
        match extract_hash_ands_signature(artifact_name) {
            Ok((expected_name, expected_hash)) => {
                if expected_name != executable_name {
                    forensic_rs::info!("Invalid prefetch executable name expected={expected_name} found={executable_name}");
                }
                if hash != expected_hash {
                    forensic_rs::info!(
                        "Invalid prefetch hash expected={expected_hash} found={hash}"
                    );
                }
            }
            Err(e) => {
                forensic_rs::info!("{}", e);
            }
        }
    }
}

fn extract_hash_ands_signature(mut name: &str) -> ForensicResult<(&str, u32)> {
    if name.ends_with(".pf") {
        name = &name[0..name.len() - 3]
    }
    name.split_once('-')
        .map(|v| (v.0, v.1.parse::<u32>().unwrap_or_default()))
        .ok_or_else(|| ForensicError::invalid_format("prefetch", "Invalid prefetch artifact name"))
}
