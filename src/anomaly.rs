//! What a prefetch file shows that its own structure or its file name contradicts.
//!
//! Each kind is kept on [`PrefetchFile::anomalies`](crate::common::PrefetchFile::anomalies) instead
//! of a log line, so it reaches the report. Only a CRC mismatch has a core
//! [`AnomalyFlags`] bit with the same meaning; the others are recorded by name (see the
//! forensic-rs `AnomalyFlags` docs on parser-specific kinds).

use std::fmt;

use forensic_rs::provenance::{AnomalyDetail, AnomalyFlags};

/// A contradiction found while parsing one prefetch file.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PrefetchAnomaly {
    /// The MAM container's CRC32 doesn't match its content. The file was still decompressed and
    /// parsed.
    CrcMismatch { stored: u32, computed: u32 },
    /// The executable name inside the file differs from the one in its file name.
    NameMismatch { file_name: String, embedded: String },
    /// The path hash inside the file differs from the one in its file name.
    HashMismatch { file_name: u32, embedded: u32 },
    /// The `.pf` file name has no `-<hex hash>` part, so name and hash can't be checked.
    NoHashInName { file_name: String },
    /// A data file (`.NLS`, `.RES`) was loaded with executable blocks.
    ExecutableBlockInDataFile { file: String },
}

impl PrefetchAnomaly {
    /// Stable name, used in output.
    pub fn name(&self) -> &'static str {
        match self {
            PrefetchAnomaly::CrcMismatch { .. } => "crc_mismatch",
            PrefetchAnomaly::NameMismatch { .. } => "name_mismatch",
            PrefetchAnomaly::HashMismatch { .. } => "hash_mismatch",
            PrefetchAnomaly::NoHashInName { .. } => "no_hash_in_name",
            PrefetchAnomaly::ExecutableBlockInDataFile { .. } => "executable_block_in_data_file",
        }
    }

    /// The core bit that means the same thing, when there is one.
    pub fn flag(&self) -> Option<AnomalyFlags> {
        match self {
            PrefetchAnomaly::CrcMismatch { .. } => Some(AnomalyFlags::CHECKSUM_MISMATCH),
            _ => None,
        }
    }

    /// Core detail for a kind that has a core bit.
    pub fn detail(&self) -> Option<AnomalyDetail> {
        self.flag()
            .map(|flag| AnomalyDetail::new(flag, self.name(), self))
    }
}

impl fmt::Display for PrefetchAnomaly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PrefetchAnomaly::CrcMismatch { stored, computed } => {
                write!(f, "stored CRC {stored:08x}, computed {computed:08x}")
            }
            PrefetchAnomaly::NameMismatch {
                file_name,
                embedded,
            } => write!(f, "file name says {file_name}, the file says {embedded}"),
            PrefetchAnomaly::HashMismatch {
                file_name,
                embedded,
            } => write!(
                f,
                "file name says {file_name:08X}, the file says {embedded:08X}"
            ),
            PrefetchAnomaly::NoHashInName { file_name } => {
                write!(f, "no -<hash> in the file name {file_name}")
            }
            PrefetchAnomaly::ExecutableBlockInDataFile { file } => {
                write!(f, "{file} was loaded with executable blocks")
            }
        }
    }
}
