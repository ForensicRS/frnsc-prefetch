use forensic_rs::err::{ForensicError, ForensicResult};

use crate::common::{u16_at_pos, u32_at_pos, u64_at_pos, utf16_at_offset, NtfsFile, PrefetchFileInformation, VolumeInformation};

pub fn volume_info_26(file_buffer : &[u8], info : &PrefetchFileInformation) -> ForensicResult<Vec<VolumeInformation>> {
    volume_info_23(file_buffer, info)
}
pub fn volume_info_30(file_buffer : &[u8], info : &PrefetchFileInformation) -> ForensicResult<Vec<VolumeInformation>> {
    let end_volume_pos = (info.volume_information_offset + info.volume_information_size) as usize;
    if end_volume_pos > file_buffer.len() {
        return Err(ForensicError::bad_format_str("The volume information position is greater than the file buffer"))
    }
    let volume_data = &file_buffer[info.volume_information_offset as usize..end_volume_pos];
    let mut volumes = Vec::with_capacity(info.volume_count as usize);
    for i in 0..(info.volume_count as usize) {
        let pos = i * 96;
        let volume_device_path_offset = u32_at_pos(volume_data, pos);
        let volume_device_path_characters =u32_at_pos(volume_data, pos + 4);
        if (volume_device_path_offset + volume_device_path_characters) as usize > volume_data.len() {
            return Err(ForensicError::bad_format_str("The device path position is greater than the volume buffer"))
        }
        let device_path = utf16_at_offset(volume_data, volume_device_path_offset as usize, volume_device_path_characters as usize)?;
        let creation_time = u64_at_pos(volume_data, pos +8);
        let serial_number = u32_at_pos(volume_data, pos +16);
        let file_references_offset = u32_at_pos(volume_data, pos +20);
        let file_references_data_size = u32_at_pos(volume_data, pos +24);
        let end_files_pos = (file_references_data_size + file_references_offset) as usize;
        if end_files_pos > volume_data.len() {
            return Err(ForensicError::bad_format_str("The files reference position is greater than the volume buffer"))
        }
        let file_data = &volume_data[file_references_offset as usize..end_files_pos];
        let file_references = extract_file_references_23(file_data)?;
        let directory_strings_offset = u32_at_pos(volume_data, pos +28);
        let directory_strings_count = u32_at_pos(volume_data, pos +32);
        if directory_strings_offset as usize > volume_data.len() {
            return Err(ForensicError::bad_format_str("The directory strings position is greater than the volume buffer"))
        }
        let directory_data = &volume_data[directory_strings_offset as usize..];
        let directory_strings = extract_directory_strings_23(directory_data, directory_strings_count as usize)?;
        volumes.push(VolumeInformation {
            device_path,
            directory_strings,
            file_references,
            creation_time,
            serial_number
        });
    }
    Ok(volumes)
}

pub fn volume_info_17(file_buffer : &[u8], info : &PrefetchFileInformation) -> ForensicResult<Vec<VolumeInformation>> {
    let end_volume_pos = (info.volume_information_offset + info.volume_information_size) as usize;
    if end_volume_pos > file_buffer.len() {
        return Err(ForensicError::bad_format_str("The volume information position is greater than the file buffer"))
    }
    let volume_data = &file_buffer[info.volume_information_offset as usize..end_volume_pos];
    let mut volumes = Vec::with_capacity(info.volume_count as usize);
    for i in 0..(info.volume_count as usize) {
        let pos = i * 40;
        let volume_device_path_offset = u32_at_pos(volume_data, pos);
        let volume_device_path_characters =u32_at_pos(volume_data, pos + 4);
        if (volume_device_path_offset + volume_device_path_characters) as usize > volume_data.len() {
            return Err(ForensicError::bad_format_str("The device path position is greater than the volume buffer"))
        }
        let device_path = utf16_at_offset(volume_data, volume_device_path_offset as usize, volume_device_path_characters as usize)?;
        let creation_time = u64_at_pos(volume_data, pos +8);
        let serial_number = u32_at_pos(volume_data, pos +16);
        let file_references_offset = u32_at_pos(volume_data, pos +20);
        let file_references_data_size = u32_at_pos(volume_data, pos +24);
        let end_files_pos = (file_references_data_size + file_references_offset) as usize;
        if end_files_pos > volume_data.len() {
            return Err(ForensicError::bad_format_str("The files reference position is greater than the volume buffer"))
        }
        let file_data = &volume_data[file_references_offset as usize..end_files_pos];
        let file_references = extract_file_references_17(file_data)?;
        let directory_strings_offset = u32_at_pos(volume_data, pos +28);
        let directory_strings_count = u32_at_pos(volume_data, pos +32);
        if directory_strings_offset as usize > volume_data.len() {
            return Err(ForensicError::bad_format_str("The directory strings position is greater than the volume buffer"))
        }
        let directory_data = &volume_data[directory_strings_offset as usize..];
        let directory_strings = extract_directory_strings_23(directory_data, directory_strings_count as usize)?;
        volumes.push(VolumeInformation {
            device_path,
            directory_strings,
            file_references,
            creation_time,
            serial_number
        });
    }
    Ok(volumes)
}

pub fn volume_info_23(file_buffer : &[u8], info : &PrefetchFileInformation) -> ForensicResult<Vec<VolumeInformation>> {
    let end_volume_pos = (info.volume_information_offset + info.volume_information_size) as usize;
    if end_volume_pos > file_buffer.len() {
        return Err(ForensicError::bad_format_str("The volume information position is greater than the file buffer"))
    }
    let volume_data = &file_buffer[info.volume_information_offset as usize..end_volume_pos];
    let mut volumes = Vec::with_capacity(info.volume_count as usize);
    for i in 0..(info.volume_count as usize) {
        let pos = i * 104;
        let volume_device_path_offset = u32_at_pos(volume_data, pos);
        let volume_device_path_characters =u32_at_pos(volume_data, pos + 4);
        if (volume_device_path_offset + volume_device_path_characters) as usize > volume_data.len() {
            return Err(ForensicError::bad_format_str("The device path position is greater than the volume buffer"))
        }
        let device_path = utf16_at_offset(volume_data, volume_device_path_offset as usize, volume_device_path_characters as usize)?;
        let creation_time = u64_at_pos(volume_data, pos +8);
        let serial_number = u32_at_pos(volume_data, pos +16);
        let file_references_offset = u32_at_pos(volume_data, pos +20);
        let file_references_data_size = u32_at_pos(volume_data, pos +24);
        let end_files_pos = (file_references_data_size + file_references_offset) as usize;
        if end_files_pos > volume_data.len() {
            return Err(ForensicError::bad_format_str("The files reference position is greater than the volume buffer"))
        }
        let file_data = &volume_data[file_references_offset as usize..end_files_pos];
        let file_references = extract_file_references_23(file_data)?;
        let directory_strings_offset = u32_at_pos(volume_data, pos +28);
        let directory_strings_count = u32_at_pos(volume_data, pos +32);
        if directory_strings_offset as usize > volume_data.len() {
            return Err(ForensicError::bad_format_str("The directory strings position is greater than the volume buffer"))
        }
        let directory_data = &volume_data[directory_strings_offset as usize..];
        let directory_strings = extract_directory_strings_23(directory_data, directory_strings_count as usize)?;
        volumes.push(VolumeInformation {
            device_path,
            directory_strings,
            file_references,
            creation_time,
            serial_number
        });
    }
    Ok(volumes)
}

fn extract_file_references_17(file_reference : &[u8]) -> ForensicResult<Vec<NtfsFile>> {
    if file_reference.len() < 8 {
        return Err(ForensicError::Other("Invalid size for file references".into()))
    }
    let file_reference_count = u32_at_pos(file_reference, 4);
    if (8 + (file_reference_count as usize * 8)) > file_reference.len() {
        return Err(ForensicError::bad_format_str("The file reference size is greater than the buffer"))
    }
    let file_reference = &file_reference[8..];
    let mut files = Vec::with_capacity(file_reference_count as usize);
    for pos in (0..(file_reference_count as usize * 8)).step_by(8) {
        let mft_entry = u64_at_pos(file_reference, pos) >> 16;
        if mft_entry == 0 {
            continue;
        }
        let seq_number = u16_at_pos(file_reference, pos + 6);
        files.push(NtfsFile {
            mft_entry,
            seq_number
        })
    }
    Ok(files)
}

fn extract_file_references_23(file_reference : &[u8]) -> ForensicResult<Vec<NtfsFile>> {
    if file_reference.len() < 16 {
        return Err(ForensicError::Other("Invalid size for file references".into()))
    }
    let file_reference_count = u32_at_pos(file_reference, 4);
    if (16 + (file_reference_count as usize * 8)) > file_reference.len() {
        return Err(ForensicError::bad_format_str("The file reference size is greater than the buffer"))
    }
    let file_reference = &file_reference[16..];
    let mut files = Vec::with_capacity(file_reference_count as usize);
    for pos in (0..(file_reference_count as usize * 8)).step_by(8) {
        let mft_entry = u64_at_pos(file_reference, pos) >> 16;
        if mft_entry == 0 {
            continue;
        }
        let seq_number = u16_at_pos(file_reference, pos + 6);
        files.push(NtfsFile {
            mft_entry,
            seq_number
        })
    }
    Ok(files)
}

fn extract_directory_strings_23(directory_strings : &[u8], count : usize) -> ForensicResult<Vec<String>> {
    if directory_strings.len() < 2 {
        return Err(ForensicError::bad_format_str("Invalid buffer size for directory strings"))
    }
    let mut list = Vec::with_capacity(count);
    let mut pos = 0;
    for _ in 0..count {
        if pos + 2 > directory_strings.len() {
            return Err(ForensicError::bad_format_str("The Directory String size is greater than the buffer size"))
        }
        let characters = u16_at_pos(directory_strings, pos) as usize;
        if pos + 4 + (characters * 2) >= directory_strings.len() {
            return Err(ForensicError::bad_format_str("The Directory String size is greater than the buffer size"))
        }
        let text = utf16_at_offset(directory_strings, pos + 2, characters * 2 + 2)?;
        pos += 4 + (characters * 2);
        list.push(text);
    }
    Ok(list)
}