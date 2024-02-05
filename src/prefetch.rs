use std::{
    io::Read,
    path::Path,
};

use forensic_rs::{
    err::{ForensicError, ForensicResult},
    notifications::NotificationType,
    notify_high, notify_low,
    traits::vfs::{VDirEntry, VirtualFile, VirtualFileSystem},
};

use crate::{common::{u32_at_pos, u64_at_pos, PrefetchFile, PrefetchFileInformation}, decompress::{decompress, CompressionAlgorithm}, metrics::*, volume::*};

const PREFETCH_SIZE_LIMIT: u64 = 1_000_000;
/// Signature = MAM
const PREFETCH_COMPRESS_SIGNATURE : u32 = u32::from_le_bytes([b'M', b'A', b'M',b'\0']);
const PREFETC_COMPRESS_SIGNATURE_U8 : &[u8] = b"MAM";

/// Reads all prefetch files on the folder C:\Windows\Prefetch.
/// 
/// ```rust
/// use forensic_rs::prelude::*;
/// use frnsc_prefetch::prelude::*;
/// let mut fs = ChRootFileSystem::new("./artifacts/17", Box::new(StdVirtualFS::new()));
/// let _list = read_prefetch_form_fs(&mut fs).expect("Must read all prefetch from filesystem");
/// ```
pub fn read_prefetch_form_fs(fs: &mut impl VirtualFileSystem) -> ForensicResult<Vec<PrefetchFile>> {
    let prefetch_folder = Path::new(r"C:\Windows\Prefetch");
    let prefetch_files = match fs.read_dir(prefetch_folder) {
        Ok(v) => v,
        Err(e) => {
            notify_high!(NotificationType::AntiForensicsDetected, "No prefetch found");
            return Err(e);
        }
    };
    let mut prefetches = Vec::with_capacity(128);
    for file in prefetch_files {
        let file_name = match file {
            VDirEntry::File(v) => v,
            _ => continue,
        };
        if !file_name.ends_with(".pf") {
            continue;
        }
        let file = fs.open(prefetch_folder.join(&file_name).as_path())?;

        match read_prefetch_file(&file_name, file) {
            Ok(v) => {
                prefetches.push(v);
            },
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
/// let mut fs = ChRootFileSystem::new("./artifacts/17", Box::new(StdVirtualFS::new()));
/// let file = fs.open(std::path::Path::new("C:\\Windows\\Prefetch\\CMD.EXE-087B4001.pf")).unwrap();
/// let _list = read_prefetch_file("CMD.EXE-087B4001.pf", file).expect("Must read all prefetch from filesystem");
/// ```
pub fn read_prefetch_file(
    artifact_name: &str,
    mut file: Box<dyn VirtualFile>
) -> ForensicResult<PrefetchFile> {
    let mut buffer = [0u8; 64];
    file.read_exact(&mut buffer)?;
    if file_is_compressed(&buffer) {
        read_prefetch_file_compressed(artifact_name, file)
    }else {
        read_prefetch_file_no_compressed(artifact_name, file)
    }
}

fn file_is_compressed(buffer : &[u8]) -> bool {
    PREFETC_COMPRESS_SIGNATURE_U8 == &buffer[0..3]
}

/// Parsers a prefetch file that is compressed.
/// 
/// ```rust
/// use forensic_rs::prelude::*;
/// use frnsc_prefetch::prelude::*;
/// use std::path::Path;
/// let mut fs = StdVirtualFS::new();
/// let file = fs.open(Path::new("./artifacts/30/C/Windows/Prefetch/RUST_OUT.EXE-5D2C8541.pf")).unwrap();
/// read_prefetch_file_compressed("RUST_OUT.EXE-5D2C8541.pf", file).unwrap();
/// ```
pub fn read_prefetch_file_compressed(
    artifact_name: &str,
    mut file: Box<dyn VirtualFile>,
) -> ForensicResult<PrefetchFile> {
    file.seek(std::io::SeekFrom::Start(0))?;
    if file.metadata()?.size > PREFETCH_SIZE_LIMIT {
        notify_low!(NotificationType::AntiForensicsDetected, "File size is abnormally large");
        return Err(ForensicError::bad_format_str("File size is abnormally large"))
    }
    let mut buffer = Vec::with_capacity(4096);
    file.read_to_end(&mut buffer)?;
    let header = &buffer[0..8];
    let compressed = &buffer[8..];
    let signature = u32::from_le_bytes(header[0..4].try_into().unwrap_or_default());
    let decompressed_size = u32::from_le_bytes(header[4..8].try_into().unwrap_or_default());
    let compress_algorithm: CompressionAlgorithm = ((signature & 0x0F000000) >> 24).into();
    let crc_ck = (signature & 0xF0000000) >> 28;
    let magic = signature & 0x00FFFFFF;
    if magic != PREFETCH_COMPRESS_SIGNATURE {
        return Err(ForensicError::bad_format_string(format!("Invalid prefetch signature: {}", magic)))
    }
    if crc_ck > 0 {
        let file_crc = u32::from_le_bytes(compressed[0..4].try_into().unwrap_or_default());
        let mut hash = crc32fast::Hasher::new();
        hash.update(&header);
        hash.update(&[0, 0, 0, 0]);
        hash.update(&compressed[4..]);
        let crc32 = hash.finalize();
        if crc32 != file_crc {
            notify_low!(
                NotificationType::AntiForensicsDetected,
                "Invalid CRC for prefetch {:?}: expected={} obtained={}",
                artifact_name, file_crc, crc32
            );
            return Err(ForensicError::bad_format_str("The CRC of the prefetch does not match"))
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
/// use std::path::Path;
/// let mut fs = StdVirtualFS::new();
/// let file = fs.open(Path::new("./artifacts/23/C/Windows/Prefetch/NOTEPAD.EXE-D8414F97.pf")).unwrap();
/// read_prefetch_file_no_compressed("NOTEPAD.EXE-D8414F97.pf", file).unwrap();
/// ```
pub fn read_prefetch_file_no_compressed(
    artifact_name: &str,
    mut file: Box<dyn VirtualFile>,
) -> ForensicResult<PrefetchFile> {
    file.seek(std::io::SeekFrom::Start(0))?;
    if file.metadata()?.size > PREFETCH_SIZE_LIMIT {
        notify_low!(NotificationType::AntiForensicsDetected, "Prefetch file {} size is abnormally large", artifact_name);
        return Err(ForensicError::bad_format_string(format!("Prefetch file {} size is abnormally large", artifact_name)))
    }
    let mut buffer = Vec::with_capacity(4096);
    file.read_to_end(&mut buffer)?;
    process_prefetch_data(artifact_name, &buffer)
}

fn process_prefetch_data(artifact_name: &str, buffer :&[u8]) -> ForensicResult<PrefetchFile> {
    let version = u32::from_le_bytes(buffer[0..4].try_into().unwrap());
    let signature = &buffer[4..8];
    if b"SCCA" != signature {
        return Err(ForensicError::bad_format_str("Invalid prefetch signature"))
    }
    //let file_size = u32::from_le_bytes(buffer[12..16].try_into().unwrap());
    let name_buffer = &buffer[16..76];
    let name_buffer :&[u16] = unsafe { std::mem::transmute(name_buffer) };
    let end = name_buffer.iter().position(|&v| v == 0).unwrap_or_else(|| name_buffer.len());
    let executable_name = String::from_utf16_lossy(&name_buffer[0..end]);
    let raw_hash = u32::from_le_bytes(buffer[76..80].try_into().unwrap());
    check_prefetch_info_correct(artifact_name, &executable_name, raw_hash);
    
    let mut prefetch_content = PrefetchFile::default();
    prefetch_content.name = executable_name;
    prefetch_content.version = version;
    if version == 17 {
        let info = file_information_17(&buffer[84..])?;
        prefetch_content.metrics = metrics_array_17(&buffer, &info)?;
        prefetch_content.volume = volume_info_17(&buffer, &info)?;
        prefetch_content.last_run_times = info.last_run_times;
        prefetch_content.run_count = info.run_count;
    } else if version == 23 {
        let info = file_information_23(&buffer[84..])?;
        prefetch_content.metrics = metrics_array_23(&buffer, &info)?;
        prefetch_content.volume = volume_info_23(&buffer, &info)?;
        prefetch_content.last_run_times = info.last_run_times;
        prefetch_content.run_count = info.run_count;
    } else if version == 26 {
        let info = file_information_26(&buffer[84..])?;
        prefetch_content.metrics = metrics_array_26(&buffer, &info)?;
        prefetch_content.volume = volume_info_26(&buffer, &info)?;
        prefetch_content.last_run_times = info.last_run_times;
        prefetch_content.run_count = info.run_count;
    } else if version == 30 {
        let info = file_information_30(&buffer[84..])?;
        prefetch_content.metrics =metrics_array_30(&buffer, &info)?;
        prefetch_content.volume = volume_info_30(&buffer, &info)?;
        prefetch_content.last_run_times = info.last_run_times;
        prefetch_content.run_count = info.run_count;
    }else {
        notify_low!(NotificationType::Informational, "The prefetch version is unknown: {}", version);
        return Err(ForensicError::bad_format_string(format!("The prefetch version is unknown: {}", version)))
    };
    Ok(prefetch_content)
}

fn file_information_17(buffer : &[u8]) -> ForensicResult<PrefetchFileInformation> {
    let metrics_offsets = u32_at_pos(buffer, 0);
    let metrics_count = u32_at_pos(buffer, 4);
    let trace_chain_offset = u32_at_pos(buffer, 8);
    let trace_chain_count = u32_at_pos(buffer, 12);
    let filename_string_offset = u32_at_pos(buffer,16);
    let filename_string_size = u32_at_pos(buffer, 20);
    let volume_information_offset = u32_at_pos(buffer, 24);
    let volume_count = u32_at_pos(buffer, 28);
    let volume_information_size = u32_at_pos(buffer, 32);
    let last_run_time = u64_at_pos(buffer, 36);
    let run_count = u32_at_pos(buffer, 60);
    Ok(PrefetchFileInformation{
        metrics_offsets,
        metrics_count,
        trace_chain_offset,
        trace_chain_count,
        filename_string_offset,
        filename_string_size,
        volume_information_offset,
        volume_information_size,
        volume_count,
        last_run_times : vec![last_run_time],
        run_count
    })
}

fn file_information_23(buffer : &[u8]) -> ForensicResult<PrefetchFileInformation> {
    let metrics_offsets = u32_at_pos(buffer, 0);
    let metrics_count = u32_at_pos(buffer, 4);
    let trace_chain_offset = u32_at_pos(buffer, 8);
    let trace_chain_count = u32_at_pos(buffer, 12);
    let filename_string_offset = u32_at_pos(buffer,16);
    let filename_string_size = u32_at_pos(buffer, 20);
    let volume_information_offset = u32_at_pos(buffer, 24);
    let volume_count = u32_at_pos(buffer, 28);
    let volume_information_size = u32_at_pos(buffer, 32);
    let last_run_time = u64_at_pos(buffer, 44);
    let run_count = u32_at_pos(buffer, 68);
    Ok(PrefetchFileInformation{
        metrics_offsets,
        metrics_count,
        trace_chain_offset,
        trace_chain_count,
        filename_string_offset,
        filename_string_size,
        volume_information_offset,
        volume_information_size,
        volume_count,
        last_run_times : vec![last_run_time],
        run_count
    })
}


fn file_information_26(buffer : &[u8]) -> ForensicResult<PrefetchFileInformation> {
    let metrics_offsets = u32_at_pos(buffer, 0);
    let metrics_count = u32_at_pos(buffer, 4);
    let trace_chain_offset = u32_at_pos(buffer, 8);
    let trace_chain_count = u32_at_pos(buffer, 12);
    let filename_string_offset = u32_at_pos(buffer,16);
    let filename_string_size = u32_at_pos(buffer, 20);
    let volume_information_offset = u32_at_pos(buffer, 24);
    let volume_count = u32_at_pos(buffer, 28);
    let volume_information_size = u32_at_pos(buffer, 32);
    let mut last_run_times = Vec::with_capacity(8);
    for i in (44..108).step_by(8) {
        let run_time = u64_at_pos(buffer, i);
        if run_time == 0 {
            continue
        }
        last_run_times.push(run_time);
    }
    let run_count = u32_at_pos(buffer, 124);
    Ok(PrefetchFileInformation{
        metrics_offsets,
        metrics_count,
        trace_chain_offset,
        trace_chain_count,
        filename_string_offset,
        filename_string_size,
        volume_information_offset,
        volume_information_size,
        volume_count,
        last_run_times,
        run_count
    })
}

fn file_information_30v1(buffer : &[u8]) -> ForensicResult<PrefetchFileInformation> {
    let metrics_offsets = u32_at_pos(buffer, 0);
    let metrics_count = u32_at_pos(buffer, 4);
    let trace_chain_offset = u32_at_pos(buffer, 8);
    let trace_chain_count = u32_at_pos(buffer, 12);
    let filename_string_offset = u32_at_pos(buffer,16);
    let filename_string_size = u32_at_pos(buffer, 20);
    let volume_information_offset = u32_at_pos(buffer, 24);
    let volume_count = u32_at_pos(buffer, 28);
    let volume_information_size = u32_at_pos(buffer, 32);
    let mut last_run_times = Vec::with_capacity(8);
    for i in (44..108).step_by(8) {
        let run_time = u64_at_pos(buffer, i);
        if run_time == 0 {
            continue
        }
        last_run_times.push(run_time);
    }
    let run_count = u32_at_pos(buffer, 124);
    Ok(PrefetchFileInformation{
        metrics_offsets,
        metrics_count,
        trace_chain_offset,
        trace_chain_count,
        filename_string_offset,
        filename_string_size,
        volume_information_offset,
        volume_information_size,
        volume_count,
        last_run_times,
        run_count
    })
}

fn file_information_30v2(buffer : &[u8]) -> ForensicResult<PrefetchFileInformation> {
    let metrics_offsets = u32_at_pos(buffer, 0);
    let metrics_count = u32_at_pos(buffer, 4);
    let trace_chain_offset = u32_at_pos(buffer, 8);
    let trace_chain_count = u32_at_pos(buffer, 12);
    let filename_string_offset = u32_at_pos(buffer,16);
    let filename_string_size = u32_at_pos(buffer, 20);
    let volume_information_offset = u32_at_pos(buffer, 24);
    let volume_count = u32_at_pos(buffer, 28);
    let volume_information_size = u32_at_pos(buffer, 32);
    let mut last_run_times = Vec::with_capacity(8);
    for i in (44..108).step_by(8) {
        let run_time = u64_at_pos(buffer, i);
        if run_time == 0 {
            continue
        }
        last_run_times.push(run_time);
    }
    let run_count = u32_at_pos(buffer, 116);
    Ok(PrefetchFileInformation{
        metrics_offsets,
        metrics_count,
        trace_chain_offset,
        trace_chain_count,
        filename_string_offset,
        filename_string_size,
        volume_information_offset,
        volume_information_size,
        volume_count,
        last_run_times,
        run_count
    })
}

fn file_information_30(buffer : &[u8]) -> ForensicResult<PrefetchFileInformation> {
    let metrics_offsets = u32::from_le_bytes(buffer[0..4].try_into().unwrap());
    if metrics_offsets == 304 {
        return file_information_30v1(buffer)
    }
    file_information_30v2(buffer)
}

fn check_prefetch_info_correct(artifact_name: &str, executable_name : &str, hash : u32) {
    if artifact_name.ends_with(".pf") {
        match extract_hash_ands_signature(artifact_name) {
            Ok((expected_name, expected_hash)) => {
                if expected_name != executable_name {
                    forensic_rs::info!("Invalid prefetch executable name expected={expected_name} found={executable_name}");
                    forensic_rs::notify_info!(NotificationType::AntiForensicsDetected, "Invalid prefetch executable name expected={expected_name} found={executable_name}");
                }
                if hash != expected_hash {
                    forensic_rs::info!("Invalid prefetch hash expected={expected_hash} found={hash}");
                    forensic_rs::notify_info!(NotificationType::AntiForensicsDetected, "Invalid prefetch hash expected={expected_hash} found={hash}");
                }
            },
            Err(e) => {
                forensic_rs::info!("{}", e);
            }
        }
    }
}

fn extract_hash_ands_signature(mut name : &str) -> ForensicResult<(&str, u32)> {
    if name.ends_with(".pf") {
        name = &name[0..name.len() - 3]
    }
    name.split_once("-").map(|v| {
        (v.0, v.1.parse::<u32>().unwrap_or_default())
    }).ok_or_else(|| ForensicError::bad_format_str("Invalid prefetch artifact name"))
}