use forensic_rs::err::{ForensicError, ForensicResult};

use crate::common::{
    checked_range, u16_at_pos, u32_at_pos, u64_at_pos, utf16_at_offset, NtfsFile,
    PrefetchFileInformation, VolumeInformation,
};

/// Parses `info.volume_count` volume-information entries out of `file_buffer`, for a given
/// per-entry `stride` (40 bytes for v17, 104 for v23/v26, 96 for v30) and the version-specific
/// `extract_file_references` sub-parser (differs only in its NTFS file-reference header size).
fn parse_volume_entries(
    file_buffer: &[u8],
    info: &PrefetchFileInformation,
    stride: usize,
    extract_file_references: fn(&[u8]) -> ForensicResult<Vec<NtfsFile>>,
) -> ForensicResult<Vec<VolumeInformation>> {
    let volume_data = &file_buffer[checked_range(
        info.volume_information_offset,
        info.volume_information_size,
        file_buffer.len(),
        "volume information",
    )?];
    let mut volumes = Vec::with_capacity(info.volume_count as usize);
    for i in 0..(info.volume_count as usize) {
        let pos = i * stride;
        let volume_device_path_offset = u32_at_pos(volume_data, pos);
        let volume_device_path_characters = u32_at_pos(volume_data, pos + 4);
        let device_path = utf16_at_offset(
            volume_data,
            volume_device_path_offset as usize,
            volume_device_path_characters as usize,
        )?;
        let creation_time = u64_at_pos(volume_data, pos + 8);
        let serial_number = u32_at_pos(volume_data, pos + 16);
        let file_references_offset = u32_at_pos(volume_data, pos + 20);
        let file_references_data_size = u32_at_pos(volume_data, pos + 24);
        let file_data = &volume_data[checked_range(
            file_references_offset,
            file_references_data_size,
            volume_data.len(),
            "file references",
        )?];
        let file_references = extract_file_references(file_data)?;
        let directory_strings_offset = u32_at_pos(volume_data, pos + 28);
        let directory_strings_count = u32_at_pos(volume_data, pos + 32);
        if directory_strings_offset as usize > volume_data.len() {
            return Err(ForensicError::invalid_format(
                "prefetch",
                "The directory strings position is greater than the volume buffer",
            ));
        }
        let directory_data = &volume_data[directory_strings_offset as usize..];
        let directory_strings =
            extract_directory_strings_23(directory_data, directory_strings_count as usize)?;
        volumes.push(VolumeInformation {
            device_path,
            directory_strings,
            file_references,
            creation_time,
            serial_number,
        });
    }
    Ok(volumes)
}

pub fn volume_info_26(
    file_buffer: &[u8],
    info: &PrefetchFileInformation,
) -> ForensicResult<Vec<VolumeInformation>> {
    volume_info_23(file_buffer, info)
}
pub fn volume_info_30(
    file_buffer: &[u8],
    info: &PrefetchFileInformation,
) -> ForensicResult<Vec<VolumeInformation>> {
    parse_volume_entries(file_buffer, info, 96, extract_file_references_23)
}

pub fn volume_info_17(
    file_buffer: &[u8],
    info: &PrefetchFileInformation,
) -> ForensicResult<Vec<VolumeInformation>> {
    parse_volume_entries(file_buffer, info, 40, extract_file_references_17)
}

pub fn volume_info_23(
    file_buffer: &[u8],
    info: &PrefetchFileInformation,
) -> ForensicResult<Vec<VolumeInformation>> {
    parse_volume_entries(file_buffer, info, 104, extract_file_references_23)
}

/// Decodes the NTFS `$MFT` file-reference array following a `header_len`-byte header
/// (8 bytes for v17, 16 bytes for v23/v26/v30): a `u64` count-in-header-plus-entries array,
/// each entry packing a 48-bit MFT entry number and a 16-bit sequence number.
fn parse_ntfs_entries(file_reference: &[u8], header_len: u32) -> ForensicResult<Vec<NtfsFile>> {
    if file_reference.len() < header_len as usize {
        return Err(ForensicError::other(
            "prefetch",
            "Invalid size for file references".to_string(),
        ));
    }
    let file_reference_count = u32_at_pos(file_reference, 4);
    let entries_range = checked_range(
        header_len,
        file_reference_count.saturating_mul(8),
        file_reference.len(),
        "file reference entries",
    )?;
    let file_reference = &file_reference[entries_range];
    let files = (0..(file_reference_count as usize * 8))
        .step_by(8)
        .filter_map(|pos| {
            let mft_entry_and_seq = u64_at_pos(file_reference, pos);
            let mft_entry = mft_entry_and_seq & 0xffffffffffff;
            if mft_entry == 0 {
                return None;
            }
            let seq_number = (mft_entry_and_seq >> 48) as u16;
            Some(NtfsFile {
                mft_entry,
                seq_number,
            })
        })
        .collect();
    Ok(files)
}

fn extract_file_references_17(file_reference: &[u8]) -> ForensicResult<Vec<NtfsFile>> {
    parse_ntfs_entries(file_reference, 8)
}

fn extract_file_references_23(file_reference: &[u8]) -> ForensicResult<Vec<NtfsFile>> {
    parse_ntfs_entries(file_reference, 16)
}

fn extract_directory_strings_23(
    directory_strings: &[u8],
    count: usize,
) -> ForensicResult<Vec<String>> {
    if directory_strings.len() < 2 {
        return Err(ForensicError::invalid_format(
            "prefetch",
            "Invalid buffer size for directory strings",
        ));
    }
    let mut list = Vec::with_capacity(count);
    let mut pos = 0;
    for _ in 0..count {
        if pos + 2 > directory_strings.len() {
            return Err(ForensicError::invalid_format(
                "prefetch",
                "The Directory String size is greater than the buffer size",
            ));
        }
        let characters = u16_at_pos(directory_strings, pos) as usize;
        if pos + 4 + (characters * 2) >= directory_strings.len() {
            return Err(ForensicError::invalid_format(
                "prefetch",
                "The Directory String size is greater than the buffer size",
            ));
        }
        let text = utf16_at_offset(directory_strings, pos + 2, characters * 2 + 2)?;
        pos += 4 + (characters * 2);
        list.push(text);
    }
    Ok(list)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ntfs_entries_decodes_valid_reference() {
        // header (8 bytes): [0..4) unused, [4..8) count=1
        // entry (8 bytes): 48-bit mft entry number | 16-bit sequence number, little-endian
        let mut buffer = vec![0u8; 16];
        buffer[4..8].copy_from_slice(&1u32.to_le_bytes());
        let packed: u64 = 0x1234_5678_9ABC | (0x0001u64 << 48);
        buffer[8..16].copy_from_slice(&packed.to_le_bytes());
        let files = extract_file_references_17(&buffer).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].mft_entry, 0x1234_5678_9ABC);
        assert_eq!(files[0].seq_number, 1);
    }

    #[test]
    fn parse_ntfs_entries_skips_zero_mft_entry() {
        let mut buffer = vec![0u8; 16];
        buffer[4..8].copy_from_slice(&1u32.to_le_bytes());
        let files = extract_file_references_17(&buffer).unwrap();
        assert!(files.is_empty());
    }

    #[test]
    fn parse_ntfs_entries_rejects_count_overflowing_the_buffer() {
        let mut buffer = vec![0u8; 16];
        buffer[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(extract_file_references_17(&buffer).is_err());
    }

    #[test]
    fn parse_ntfs_entries_rejects_buffer_shorter_than_header() {
        let buffer = vec![0u8; 4]; // shorter than the 8-byte v17 header
        assert!(extract_file_references_17(&buffer).is_err());
    }

    #[test]
    fn extract_file_references_23_decodes_valid_reference() {
        // 16-byte header: [4..8) count=1; entries start at byte 16 (vs. byte 8 for the
        // 8-byte v17 header) — same count-field position, different entry-array start.
        let mut buffer = vec![0u8; 24];
        buffer[4..8].copy_from_slice(&1u32.to_le_bytes());
        let packed: u64 = 0x1111_2222_3333 | (0x0007u64 << 48);
        buffer[16..24].copy_from_slice(&packed.to_le_bytes());
        let files = extract_file_references_23(&buffer).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].mft_entry, 0x1111_2222_3333);
        assert_eq!(files[0].seq_number, 7);
    }

    #[test]
    fn extract_directory_strings_23_decodes_single_string() {
        // one entry: characters=2 (u16) + utf16 "AB" + NUL terminator (6 bytes) = 8 bytes,
        // plus 2 trailing padding bytes so the buffer is strictly longer than the entry
        // (the bounds check below is `>=`, not `>`).
        let mut buffer = vec![0u8; 10];
        buffer[0..2].copy_from_slice(&2u16.to_le_bytes());
        buffer[2..4].copy_from_slice(&0x0041u16.to_le_bytes());
        buffer[4..6].copy_from_slice(&0x0042u16.to_le_bytes());
        let strings = extract_directory_strings_23(&buffer, 1).unwrap();
        assert_eq!(strings, vec!["AB".to_string()]);
    }

    /// Builds a single volume-information entry (given `stride`) with no NTFS file references
    /// and no directory strings, plus a trailing "C" device-path string — shared by the
    /// `volume_info_23`/`_26`/`_30` happy-path tests below, which only differ in `stride`.
    fn single_entry_volume_buffer(stride: u32) -> (Vec<u8>, PrefetchFileInformation) {
        let file_refs_offset = stride;
        let device_path_offset = stride + 16;
        let mut buffer = vec![0u8; device_path_offset as usize + 2];
        buffer[0..4].copy_from_slice(&device_path_offset.to_le_bytes());
        buffer[4..8].copy_from_slice(&2u32.to_le_bytes()); // device path: 2 bytes = 1 UTF-16 unit
        buffer[8..16].copy_from_slice(&0x1000u64.to_le_bytes()); // creation_time
        buffer[16..20].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes()); // serial_number
        buffer[20..24].copy_from_slice(&file_refs_offset.to_le_bytes());
        buffer[24..28].copy_from_slice(&16u32.to_le_bytes()); // file references: 16-byte header, count=0
        buffer[28..32].copy_from_slice(&0u32.to_le_bytes()); // directory_strings_offset = 0
        buffer[32..36].copy_from_slice(&0u32.to_le_bytes()); // directory_strings_count = 0
        // file_refs region ([stride..stride+16)) stays all-zero: a valid 16-byte header with count=0
        let device_path_offset = device_path_offset as usize;
        buffer[device_path_offset..device_path_offset + 2].copy_from_slice(b"C\0");
        let info = PrefetchFileInformation {
            volume_information_offset: 0,
            volume_information_size: u32::try_from(buffer.len()).unwrap(),
            volume_count: 1,
            ..Default::default()
        };
        (buffer, info)
    }

    #[test]
    fn volume_info_23_decodes_single_entry_with_no_files_or_directories() {
        let (buffer, info) = single_entry_volume_buffer(104);
        let volumes = volume_info_23(&buffer, &info).unwrap();
        assert_eq!(volumes.len(), 1);
        assert_eq!(volumes[0].device_path, "C");
        assert_eq!(volumes[0].serial_number, 0xDEAD_BEEF);
        assert_eq!(volumes[0].creation_time, 0x1000);
        assert!(volumes[0].file_references.is_empty());
        assert!(volumes[0].directory_strings.is_empty());
    }

    #[test]
    fn volume_info_26_decodes_single_entry_with_no_files_or_directories() {
        // volume_info_26 delegates straight to volume_info_23, so it shares its 104-byte stride.
        let (buffer, info) = single_entry_volume_buffer(104);
        let volumes = volume_info_26(&buffer, &info).unwrap();
        assert_eq!(volumes.len(), 1);
        assert_eq!(volumes[0].device_path, "C");
    }

    #[test]
    fn volume_info_30_decodes_single_entry_with_no_files_or_directories() {
        let (buffer, info) = single_entry_volume_buffer(96);
        let volumes = volume_info_30(&buffer, &info).unwrap();
        assert_eq!(volumes.len(), 1);
        assert_eq!(volumes[0].device_path, "C");
        assert_eq!(volumes[0].serial_number, 0xDEAD_BEEF);
    }

    #[test]
    fn volume_info_17_rejects_truncated_volume_information() {
        let info = PrefetchFileInformation {
            volume_information_offset: 0,
            volume_count: 1,
            volume_information_size: 1000, // far larger than the buffer below
            ..Default::default()
        };
        let buffer = vec![0u8; 10];
        assert!(volume_info_17(&buffer, &info).is_err());
    }

    #[test]
    fn volume_info_17_rejects_device_path_overflowing_volume_buffer() {
        // volume_information_size covers exactly one 40-byte entry, but the entry's
        // device-path offset/length point past the end of that slice.
        let mut buffer = vec![0u8; 40];
        buffer[0..4].copy_from_slice(&0u32.to_le_bytes());
        buffer[4..8].copy_from_slice(&u32::MAX.to_le_bytes()); // characters, absurdly large
        let info = PrefetchFileInformation {
            volume_information_offset: 0,
            volume_count: 1,
            volume_information_size: 40,
            ..Default::default()
        };
        assert!(volume_info_17(&buffer, &info).is_err());
    }
}
