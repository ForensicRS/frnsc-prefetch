use forensic_rs::err::{ForensicError, ForensicResult};

/// By default blocks will be loaded into executable memory sections
pub const FLAG_PROGRAM_BLOCK_EXECUTABLE: u32 = 0x0200;

/// By default blocks will be loaded as resources, not executable
pub const FLAG_PROGRAM_BLOCK_RESOURCE: u32 = 0x0002;

/// By default blocks should not be prefetched, should be pulled from disk.
pub const FLAG_PROGRAM_BLOCK_DONT_PREFETCH: u32 = 0x0001;

/// The block is loaded into a executable memory section
pub const FLAG_BLOCK_EXECUTABLE: u8 = 0x02;

/// The block is loaded as resouce
pub const FLAG_BLOCK_RESOURCE: u8 = 0x04;
/// The block is forced to be prefetched
pub const FLAG_BLOCK_FORCE_PREFETCH: u8 = 0x08;
/// The block will not be prefetched, should be pulled from disk.
pub const FLAG_BLOCK_DONT_PREFETCH: u8 = 0x01;

#[derive(Debug, Clone, Default)]
pub struct PrefetchFile {
    /// Prefetch file version
    pub version: u32,
    /// Executable name
    pub name: String,
    /// List of DLLs/EXEs loaded by the executable
    pub metrics: Vec<Metric>,
    /// Last execution times (max 8)
    pub last_run_times: Vec<u64>,
    /// Number of times executed
    pub run_count: u32,
    /// Information about the disks and other volumes
    pub volume: Vec<VolumeInformation>,
}
#[derive(Clone, Debug, Default)]
pub struct PrefetchFileInformation {
    pub metrics_offsets: u32,
    pub metrics_count: u32,
    pub trace_chain_offset: u32,
    pub trace_chain_count: u32,
    pub filename_string_offset: u32,
    pub filename_string_size: u32,
    pub volume_information_offset: u32,
    pub volume_count: u32,
    pub volume_information_size: u32,
    pub last_run_times: Vec<u64>,
    pub run_count: u32,
}

/// Files loaded by the executable
#[derive(Debug, Clone, Default)]
pub struct Metric {
    /// Full path to the dependency. Ex: File=\VOLUME{01d962d37536cd21-a2691d2c}\WINDOWS\SYSTEM32\NTDLL.DLL
    pub file: String,
    /// Default flags for loading blocks: executable, resource or non-prefetchable.
    pub flags: PrefetchFlag,
    /// Number of blocks to be prefetched
    pub blocks_to_prefetch: u32,
    /// Traces for this dependency
    pub traces: Vec<Trace>,
}
#[derive(Debug, Clone, Default)]
pub struct Trace {
    /// Flags for loading blocks: executable, resource, non-prefetchable or force prefetch.
    pub flags: BlockFlags,
    /// Memory block offset
    pub block_offset: u32,
    /// Stores whether the block was used in each of the last eight runs (1 bit each)
    pub used_bitfield: u8,
    /// Stores whether the block was prefetched in each of the last eight runs (1 bit each)
    pub prefetched_bitfield: u8,
}
#[derive(Clone, Default)]
pub struct PrefetchFlag(u32);

impl PrefetchFlag {
    pub fn is_executable(&self) -> bool {
        self.0 & FLAG_PROGRAM_BLOCK_EXECUTABLE > 0
    }
    pub fn is_resource(&self) -> bool {
        self.0 & FLAG_PROGRAM_BLOCK_RESOURCE > 0
    }
    pub fn is_not_prefetched(&self) -> bool {
        self.0 & FLAG_PROGRAM_BLOCK_DONT_PREFETCH > 0
    }
}
impl From<u32> for PrefetchFlag {
    fn from(value: u32) -> Self {
        Self(value)
    }
}
impl core::fmt::Debug for PrefetchFlag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut writed = 0;
        if self.is_executable() {
            f.write_str("X")?;
            writed += 1;
        }
        if self.is_resource() {
            f.write_str("R")?;
            writed += 1;
        }
        if self.is_not_prefetched() {
            f.write_str("D")?;
            writed += 1;
        }
        if writed == 0 {
            f.write_str("-")?;
        }
        Ok(())
    }
}

impl core::fmt::Display for PrefetchFlag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut writed = 0;
        if self.is_executable() {
            f.write_str("X")?;
            writed += 1;
        }
        if self.is_resource() {
            f.write_str("R")?;
            writed += 1;
        }
        if self.is_not_prefetched() {
            f.write_str("D")?;
            writed += 1;
        }
        if writed == 0 {
            f.write_str("-")?;
        }
        Ok(())
    }
}
#[derive(Clone, Default)]
pub struct BlockFlags(u8);

impl BlockFlags {
    pub fn is_executable(&self) -> bool {
        self.0 & FLAG_BLOCK_EXECUTABLE > 0
    }
    pub fn is_resource(&self) -> bool {
        self.0 & FLAG_BLOCK_RESOURCE > 0
    }
    pub fn is_not_prefetched(&self) -> bool {
        self.0 & FLAG_BLOCK_DONT_PREFETCH > 0
    }
    pub fn is_force_prefetch(&self) -> bool {
        self.0 & FLAG_BLOCK_FORCE_PREFETCH > 0
    }
}

impl core::fmt::Debug for BlockFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut writed = 0;
        if self.is_executable() {
            f.write_str("X")?;
            writed += 1;
        }
        if self.is_resource() {
            f.write_str("R")?;
            writed += 1;
        }
        if self.is_force_prefetch() {
            f.write_str("F")?;
            writed += 1;
        }
        if self.is_not_prefetched() {
            f.write_str("D")?;
            writed += 1;
        }
        if writed == 0 {
            f.write_str("-")?;
        }
        Ok(())
    }
}

impl From<u8> for BlockFlags {
    fn from(value: u8) -> Self {
        Self(value)
    }
}

impl core::fmt::Display for BlockFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut writed = 0;
        if self.is_executable() {
            f.write_str("X")?;
            writed += 1;
        }
        if self.is_resource() {
            f.write_str("R")?;
            writed += 1;
        }
        if self.is_force_prefetch() {
            f.write_str("F")?;
            writed += 1;
        }
        if self.is_not_prefetched() {
            f.write_str("D")?;
            writed += 1;
        }
        if writed == 0 {
            f.write_str("-")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct VolumeInformation {
    pub device_path: String,
    pub file_references: Vec<NtfsFile>,
    pub directory_strings: Vec<String>,
    pub creation_time: u64,
    pub serial_number: u32,
}

#[derive(Debug, Clone, Default)]
pub struct NtfsFile {
    pub mft_entry: u64,
    pub seq_number: u16,
}

pub fn utf16_at_offset(file_buffer: &[u8], offset: usize, size: usize) -> ForensicResult<String> {
    let end_pos = offset + size;
    if end_pos > file_buffer.len() {
        return Err(ForensicError::bad_format_str(
            "The utf16 string position is greater than the file buffer",
        ));
    }
    let txt = &file_buffer[offset..end_pos];
    let txt_u16: &[u16] = unsafe { std::mem::transmute(txt) };
    let end = txt_u16
        .iter()
        .position(|&v| v == 0)
        .unwrap_or(txt_u16.len());
    let txt = String::from_utf16_lossy(&txt_u16[0..end]);
    Ok(txt)
}

pub fn u16_at_pos(buffer: &[u8], pos: usize) -> u16 {
    u16::from_le_bytes(buffer[pos..pos + 2].try_into().unwrap_or_default())
}
pub fn u32_at_pos(buffer: &[u8], pos: usize) -> u32 {
    u32::from_le_bytes(buffer[pos..pos + 4].try_into().unwrap_or_default())
}
pub fn u64_at_pos(buffer: &[u8], pos: usize) -> u64 {
    u64::from_le_bytes(buffer[pos..pos + 8].try_into().unwrap_or_default())
}

impl Metric {
    pub fn has_executable_block(&self) -> bool {
        for trace in self.traces.iter() {
            if trace.flags.is_executable() {
                return true;
            }
        }
        false
    }
}
