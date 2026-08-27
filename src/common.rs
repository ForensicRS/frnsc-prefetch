use std::{borrow::Cow, collections::BTreeMap};

use forensic_rs::{
    activity::{ForensicActivity, ProgramExecution, SessionId},
    data::ForensicData,
    dictionary::*,
    err::{ForensicError, ForensicResult},
    field::{Field, Text},
    provenance::{Acquisition, ProvenanceId, ProvenanceStore, Recovery, SourceKey},
    traits::forensic::{IntoActivity, IntoTimeline, TimeContext, TimelineData},
    utils::time::Filetime,
};

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
    pub last_run_times: Vec<Filetime>,
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
    pub last_run_times: Vec<Filetime>,
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
        core::fmt::Debug::fmt(self, f)
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
        core::fmt::Debug::fmt(self, f)
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

/// Bounds-checks `offset..offset+len` against `buffer_len`, widening to `u64` first so a
/// corrupt/adversarial `offset`/`len` pair can't overflow `u32` and defeat the check.
pub(crate) fn checked_range(
    offset: u32,
    len: u32,
    buffer_len: usize,
    field: &'static str,
) -> ForensicResult<std::ops::Range<usize>> {
    let end = offset as u64 + len as u64;
    if end as usize > buffer_len {
        return Err(ForensicError::invalid_format(
            "prefetch",
            format!("{field}: position is greater than the file buffer"),
        ));
    }
    Ok(offset as usize..end as usize)
}

pub fn utf16_at_offset(file_buffer: &[u8], offset: usize, size: usize) -> ForensicResult<String> {
    let end_pos = offset + size;
    if end_pos > file_buffer.len() {
        return Err(ForensicError::invalid_format(
            "prefetch",
            "The utf16 string position is greater than the file buffer",
        ));
    }
    let txt = &file_buffer[offset..end_pos];
    let units: Vec<u16> = txt
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let end = units.iter().position(|&v| v == 0).unwrap_or(units.len());
    Ok(String::from_utf16_lossy(&units[0..end]))
}

/// Reads a little-endian `u16` at `pos`, defaulting to `0` if `pos..pos+2` is out of bounds.
/// Uses `buffer.get(..)` rather than direct slicing: a plain `buffer[pos..pos + 2]` panics on
/// an out-of-range `pos` before any fallback logic can run.
pub fn u16_at_pos(buffer: &[u8], pos: usize) -> u16 {
    buffer
        .get(pos..pos + 2)
        .and_then(|s| s.try_into().ok())
        .map(u16::from_le_bytes)
        .unwrap_or_default()
}
pub fn u32_at_pos(buffer: &[u8], pos: usize) -> u32 {
    buffer
        .get(pos..pos + 4)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_le_bytes)
        .unwrap_or_default()
}
pub fn u64_at_pos(buffer: &[u8], pos: usize) -> u64 {
    buffer
        .get(pos..pos + 8)
        .and_then(|s| s.try_into().ok())
        .map(u64::from_le_bytes)
        .unwrap_or_default()
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

impl PrefetchFile {
    pub fn new() -> Self {
        PrefetchFile::default()
    }

    pub fn executable_path(&self) -> &str {
        for loaded in &self.metrics {
            if loaded.file.ends_with(&self.name) {
                return &loaded.file;
            }
        }
        &self.name
    }
    /// Gets for which user was the program executed. Its not precise.
    pub fn user(&self) -> Option<&str> {
        for volume in &self.volume {
            for file in &volume.directory_strings {
                if !file.starts_with(r"\") {
                    continue;
                }
                let filename = &file[1..];
                let mut splited = filename.split(r"\");
                if splited.next().is_none() {
                    continue;
                };
                match splited.next() {
                    Some("USERS") => {}
                    _ => continue,
                };
                let user = match splited.next() {
                    Some(v) => v,
                    None => continue,
                };
                match splited.next() {
                    Some("APPDATA") => {}
                    _ => continue,
                };
                return Some(user);
            }
        }
        None
    }
}

/// Mints a fresh provenance id for a standalone (non-pipeline) conversion of a single
/// [`PrefetchFile`]. Every record derived from the same file shares this id.
fn mint_provenance(name: &str) -> ProvenanceId {
    ProvenanceStore::new()
        .register_source(SourceKey::Path(name.to_string()))
        .mint(Acquisition::ImageRead, Recovery::Allocated)
}

pub struct PrefetchTimelineIterator<'a> {
    prefetch: &'a PrefetchFile,
    time_pos: usize,
    provenance: ProvenanceId,
}
impl<'a> Iterator for PrefetchTimelineIterator<'a> {
    type Item = ForensicResult<TimelineData>;
    fn next(&mut self) -> Option<Self::Item> {
        let actual_pos = self.time_pos;
        if actual_pos >= self.prefetch.last_run_times.len() {
            return None;
        }
        self.time_pos += 1;
        let ctx = forensic_rs::context::context();
        let mut data = ForensicData::new(&ctx.host, ctx.artifact.clone(), self.provenance);
        data.add_field(
            FILE_ACCESSED,
            self.prefetch.last_run_times[actual_pos].into(),
        );
        data.add_field(
            FILE_PATH,
            Field::Text(Cow::Owned(self.prefetch.name.clone())),
        );
        let dependencies: Vec<Text> = self
            .prefetch
            .metrics
            .iter()
            .map(|v| Cow::Owned(v.file.clone()))
            .collect();
        data.add_field(PE_IMPORTS, Field::Array(dependencies));
        data.add_field("prefetch.execution_times", self.prefetch.run_count.into());
        data.add_field("prefetch.version", self.prefetch.version.into());
        let mut volume_files = Vec::with_capacity(1024);
        for volumn in self.prefetch.volume.iter() {
            for files in volumn.directory_strings.iter() {
                volume_files.push(Cow::Owned(files.clone()))
            }
        }
        data.add_field("prefetch.volume_files", Field::Array(volume_files));
        Some(Ok(TimelineData {
            time: self.prefetch.last_run_times[actual_pos].into(),
            data,
            time_context: TimeContext::Accessed,
        }))
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.time_pos, Some(self.prefetch.last_run_times.len()))
    }
}

pub struct PrefetchActivityIterator<'a> {
    prefetch: &'a PrefetchFile,
    time_pos: usize,
}
impl<'a> Iterator for PrefetchActivityIterator<'a> {
    type Item = ForensicResult<ForensicActivity>;
    fn next(&mut self) -> Option<Self::Item> {
        let actual_pos = self.time_pos;
        if actual_pos >= self.prefetch.last_run_times.len() {
            return None;
        }
        self.time_pos += 1;
        Some(Ok(ForensicActivity {
            timestamp: self.prefetch.last_run_times[actual_pos].into(),
            activity: ProgramExecution::new(self.prefetch.executable_path().to_string()).into(),
            user: self
                .prefetch
                .user()
                .map(|v| v.to_string())
                .unwrap_or_default(),
            session_id: SessionId::Unknown,
            extras: BTreeMap::new(),
        }))
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.time_pos, Some(self.prefetch.last_run_times.len()))
    }
}

impl<'a> IntoActivity<'a> for &'a PrefetchFile {
    fn activity(&'a self) -> Self::IntoIter {
        PrefetchActivityIterator {
            prefetch: self,
            time_pos: 0,
        }
    }

    type IntoIter
        = PrefetchActivityIterator<'a>
    where
        Self: 'a;
}

impl<'a> IntoActivity<'a> for PrefetchFile {
    fn activity(&'a self) -> Self::IntoIter {
        PrefetchActivityIterator {
            prefetch: self,
            time_pos: 0,
        }
    }

    type IntoIter
        = PrefetchActivityIterator<'a>
    where
        Self: 'a;
}

impl<'a> IntoTimeline<'a> for &'a PrefetchFile {
    fn timeline(&'a self) -> Self::IntoIter {
        PrefetchTimelineIterator {
            prefetch: self,
            time_pos: 0,
            provenance: mint_provenance(&self.name),
        }
    }

    type IntoIter
        = PrefetchTimelineIterator<'a>
    where
        Self: 'a;
}

impl<'a> IntoTimeline<'a> for PrefetchFile {
    fn timeline(&'a self) -> Self::IntoIter {
        PrefetchTimelineIterator {
            prefetch: self,
            time_pos: 0,
            provenance: mint_provenance(&self.name),
        }
    }

    type IntoIter
        = PrefetchTimelineIterator<'a>
    where
        Self: 'a;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf16_at_offset_decodes_nul_terminated_string() {
        // "AB" + NUL + trailing bytes that must be ignored
        let buffer = [0x41, 0x00, 0x42, 0x00, 0x00, 0x00, 0xFF, 0xFF];
        let text = utf16_at_offset(&buffer, 0, 8).unwrap();
        assert_eq!(text, "AB");
    }

    #[test]
    fn utf16_at_offset_uses_full_size_when_no_nul() {
        let buffer = [0x41, 0x00, 0x42, 0x00];
        let text = utf16_at_offset(&buffer, 0, 4).unwrap();
        assert_eq!(text, "AB");
    }

    #[test]
    fn utf16_at_offset_rejects_out_of_bounds_range() {
        let buffer = [0x41, 0x00];
        assert!(utf16_at_offset(&buffer, 0, 4).is_err());
    }

    #[test]
    fn utf16_at_offset_empty_size_yields_empty_string() {
        let buffer = [0x41, 0x00];
        let text = utf16_at_offset(&buffer, 0, 0).unwrap();
        assert_eq!(text, "");
    }

    #[test]
    fn checked_range_rejects_overflowing_offset_and_len() {
        // offset + len would overflow u32 if computed naively
        assert!(checked_range(u32::MAX, 2, 100, "test field").is_err());
    }

    #[test]
    fn checked_range_accepts_in_bounds_range() {
        let range = checked_range(2, 4, 10, "test field").unwrap();
        assert_eq!(range, 2..6);
    }

    #[test]
    fn u16_u32_u64_at_pos_read_little_endian() {
        let buffer = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert_eq!(u16_at_pos(&buffer, 0), 0x0201);
        assert_eq!(u32_at_pos(&buffer, 0), 0x04030201);
        assert_eq!(u64_at_pos(&buffer, 0), 0x0807060504030201);
    }

    #[test]
    fn u32_at_pos_defaults_to_zero_when_out_of_bounds() {
        let buffer = [0x01, 0x02];
        assert_eq!(u32_at_pos(&buffer, 0), 0);
    }

    #[test]
    fn prefetch_flag_debug_and_display_agree() {
        let flag: PrefetchFlag = FLAG_PROGRAM_BLOCK_EXECUTABLE.into();
        assert_eq!(format!("{:?}", flag), "X");
        assert_eq!(format!("{flag}"), "X");
    }

    #[test]
    fn prefetch_flag_defaults_to_dash_when_no_bits_set() {
        let flag: PrefetchFlag = 0u32.into();
        assert_eq!(format!("{:?}", flag), "-");
    }

    #[test]
    fn block_flags_debug_and_display_agree() {
        let flags: BlockFlags = (FLAG_BLOCK_EXECUTABLE | FLAG_BLOCK_FORCE_PREFETCH).into();
        assert_eq!(format!("{:?}", flags), "XF");
        assert_eq!(format!("{flags}"), "XF");
    }

    #[test]
    fn executable_path_falls_back_to_name_without_matching_metric() {
        let prefetch = PrefetchFile {
            name: "CMD.EXE".to_string(),
            ..Default::default()
        };
        assert_eq!(prefetch.executable_path(), "CMD.EXE");
    }

    #[test]
    fn executable_path_prefers_matching_metric_full_path() {
        let prefetch = PrefetchFile {
            name: "CMD.EXE".to_string(),
            metrics: vec![Metric {
                file: r"\VOLUME{...}\WINDOWS\SYSTEM32\CMD.EXE".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert_eq!(
            prefetch.executable_path(),
            r"\VOLUME{...}\WINDOWS\SYSTEM32\CMD.EXE"
        );
    }

    #[test]
    fn user_extracts_username_from_well_formed_path() {
        let prefetch = PrefetchFile {
            volume: vec![VolumeInformation {
                directory_strings: vec![r"\VOLUME{GUID}\USERS\ALICE\APPDATA\LOCAL".to_string()],
                ..Default::default()
            }],
            ..Default::default()
        };
        assert_eq!(prefetch.user(), Some("ALICE"));
    }

    #[test]
    fn user_returns_none_without_users_segment() {
        let prefetch = PrefetchFile {
            volume: vec![VolumeInformation {
                directory_strings: vec![r"\VOLUME{GUID}\WINDOWS\SYSTEM32".to_string()],
                ..Default::default()
            }],
            ..Default::default()
        };
        assert_eq!(prefetch.user(), None);
    }

    #[test]
    fn user_returns_none_without_any_volumes() {
        let prefetch = PrefetchFile::default();
        assert_eq!(prefetch.user(), None);
    }
}
