use forensic_rs::err::{ForensicError, ForensicResult};

use crate::common::{checked_range, u32_at_pos, PrefetchFileInformation, Trace};

/// Bounds-checks and slices the trace chain array for a given per-entry `stride`
/// (12 bytes for v17, 8 bytes for v30).
fn trace_chain_slice<'a>(
    file_buffer: &'a [u8],
    info: &PrefetchFileInformation,
    stride: u32,
) -> ForensicResult<&'a [u8]> {
    let range = checked_range(
        info.trace_chain_offset,
        info.trace_chain_count.saturating_mul(stride),
        file_buffer.len(),
        "trace chain array",
    )?;
    Ok(&file_buffer[range])
}

/// Bounds-checks `index..index+size` (entry counts, not bytes) against a trace array already
/// sliced by [`trace_chain_slice`], widening to `u64` so an attacker-controlled index/size
/// pair can't overflow before the stride multiply.
fn checked_entry_range(
    index: usize,
    size: usize,
    stride: usize,
    trace_array_len: usize,
) -> ForensicResult<()> {
    let end = (index as u64 + size as u64) * stride as u64;
    if end > trace_array_len as u64 {
        return Err(ForensicError::invalid_format(
            "prefetch",
            "The trace array position is greater than the file buffer length",
        ));
    }
    Ok(())
}

pub fn traces_for_dependency_v17(
    file_buffer: &[u8],
    info: &PrefetchFileInformation,
    index: usize,
    size: usize,
) -> ForensicResult<Vec<Trace>> {
    let trace_array = trace_chain_slice(file_buffer, info, 12)?;
    checked_entry_range(index, size, 12, trace_array.len())?;
    let mut traces = Vec::with_capacity(size);
    for i in 0..size {
        let pos = (index + i) * 12;
        let entry = &trace_array[pos..];
        let block_offset = u32_at_pos(entry, 4);
        let flags = entry[8];
        traces.push(Trace {
            flags: flags.into(),
            block_offset,
            used_bitfield: entry[10],
            prefetched_bitfield: entry[11],
        });
    }
    Ok(traces)
}

pub fn process_trace_chain_v17(
    file_buffer: &[u8],
    info: &PrefetchFileInformation,
) -> ForensicResult<Vec<Trace>> {
    let trace_array = trace_chain_slice(file_buffer, info, 12)?;
    let mut traces = Vec::with_capacity(info.trace_chain_count as usize);
    for i in 0..(info.trace_chain_count as usize) {
        let pos = i * 12;
        let entry = &trace_array[pos..];
        let block_offset = u32_at_pos(entry, 4);
        let flags = entry[8];
        traces.push(Trace {
            flags: flags.into(),
            block_offset,
            used_bitfield: entry[10],
            prefetched_bitfield: entry[11],
        });
    }
    Ok(traces)
}
pub fn process_trace_chain_v30(
    file_buffer: &[u8],
    info: &PrefetchFileInformation,
) -> ForensicResult<Vec<Trace>> {
    let trace_array = trace_chain_slice(file_buffer, info, 8)?;
    let mut traces = Vec::with_capacity(info.trace_chain_count as usize);
    for i in 0..(info.trace_chain_count as usize) {
        let pos = i * 8;
        let entry = &trace_array[pos..];
        let block_offset = u32_at_pos(entry, 0);
        let flags = entry[4];
        traces.push(Trace {
            flags: flags.into(),
            block_offset,
            used_bitfield: entry[6],
            prefetched_bitfield: entry[7],
        });
    }
    Ok(traces)
}
pub fn traces_for_dependency_v30(
    file_buffer: &[u8],
    info: &PrefetchFileInformation,
    index: usize,
    size: usize,
) -> ForensicResult<Vec<Trace>> {
    let trace_array = trace_chain_slice(file_buffer, info, 8)?;
    checked_entry_range(index, size, 8, trace_array.len())?;
    let mut traces = Vec::with_capacity(size);
    for i in 0..size {
        let pos = (index + i) * 8;
        let entry = &trace_array[pos..];
        let block_offset = u32_at_pos(entry, 0);
        let flags = entry[4].into();
        traces.push(Trace {
            flags,
            block_offset,
            used_bitfield: entry[6],
            prefetched_bitfield: entry[7],
        });
    }
    Ok(traces)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v17_info(trace_chain_offset: u32, trace_chain_count: u32) -> PrefetchFileInformation {
        PrefetchFileInformation {
            trace_chain_offset,
            trace_chain_count,
            ..Default::default()
        }
    }

    #[test]
    fn process_trace_chain_v17_decodes_single_entry() {
        // stride 12: [0..4) trace_index (unused here), [4..8) block_offset, [8] flags,
        // [9] reserved, [10] used_bitfield, [11] prefetched_bitfield
        let mut buffer = vec![0u8; 12];
        buffer[4..8].copy_from_slice(&0x1234u32.to_le_bytes());
        buffer[8] = crate::common::FLAG_BLOCK_EXECUTABLE;
        buffer[10] = 0xAA;
        buffer[11] = 0x55;
        let info = v17_info(0, 1);
        let traces = process_trace_chain_v17(&buffer, &info).unwrap();
        assert_eq!(traces.len(), 1);
        assert_eq!(traces[0].block_offset, 0x1234);
        assert_eq!(traces[0].used_bitfield, 0xAA);
        assert_eq!(traces[0].prefetched_bitfield, 0x55);
        assert!(traces[0].flags.is_executable());
    }

    #[test]
    fn process_trace_chain_v17_rejects_truncated_buffer() {
        let info = v17_info(0, 5); // claims 5 entries but the buffer only holds 1
        let buffer = vec![0u8; 12];
        assert!(process_trace_chain_v17(&buffer, &info).is_err());
    }

    #[test]
    fn process_trace_chain_v17_rejects_overflowing_count_instead_of_panicking() {
        // trace_chain_count * 12 would overflow u32 if computed naively
        let info = v17_info(0, u32::MAX);
        let buffer = vec![0u8; 12];
        assert!(process_trace_chain_v17(&buffer, &info).is_err());
    }

    #[test]
    fn traces_for_dependency_v17_reads_requested_subrange() {
        let mut buffer = vec![0u8; 24]; // 2 entries
        buffer[16..20].copy_from_slice(&0xAAAAu32.to_le_bytes()); // second entry's block_offset
        let info = v17_info(0, 2);
        let traces = traces_for_dependency_v17(&buffer, &info, 1, 1).unwrap();
        assert_eq!(traces.len(), 1);
        assert_eq!(traces[0].block_offset, 0xAAAA);
    }

    #[test]
    fn traces_for_dependency_v17_rejects_index_size_past_the_chain() {
        let buffer = vec![0u8; 12]; // 1 entry
        let info = v17_info(0, 1);
        assert!(traces_for_dependency_v17(&buffer, &info, 0, 5).is_err());
    }

    #[test]
    fn process_trace_chain_v30_decodes_single_entry() {
        // stride 8: [0..4) block_offset, [4] flags, [5] reserved, [6] used, [7] prefetched
        let mut buffer = vec![0u8; 8];
        buffer[0..4].copy_from_slice(&0x9999u32.to_le_bytes());
        buffer[6] = 0x11;
        buffer[7] = 0x22;
        let info = PrefetchFileInformation {
            trace_chain_offset: 0,
            trace_chain_count: 1,
            ..Default::default()
        };
        let traces = process_trace_chain_v30(&buffer, &info).unwrap();
        assert_eq!(traces.len(), 1);
        assert_eq!(traces[0].block_offset, 0x9999);
        assert_eq!(traces[0].used_bitfield, 0x11);
        assert_eq!(traces[0].prefetched_bitfield, 0x22);
    }

    #[test]
    fn traces_for_dependency_v30_rejects_overflowing_index_size() {
        let buffer = vec![0u8; 8]; // 1 entry
        let info = PrefetchFileInformation {
            trace_chain_offset: 0,
            trace_chain_count: 1,
            ..Default::default()
        };
        // index/size originate from u32 fields (metrics.rs's trace_index/trace_size), so
        // u32::MAX is the realistic worst case an attacker-controlled file can produce; this
        // must be rejected as out of range rather than wrapping/overflowing the stride multiply.
        let huge = u32::MAX as usize;
        assert!(traces_for_dependency_v30(&buffer, &info, huge, huge).is_err());
    }
}
