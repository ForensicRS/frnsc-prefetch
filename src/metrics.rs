use forensic_rs::err::ForensicResult;

use crate::{
    common::{checked_range, u32_at_pos, utf16_at_offset, Metric, PrefetchFileInformation, Trace},
    trace::{traces_for_dependency_v17, traces_for_dependency_v30},
};

type TracesForDependencyFn =
    fn(&[u8], &PrefetchFileInformation, usize, usize) -> ForensicResult<Vec<Trace>>;

/// Extracts `(trace_index, trace_size, blocks_to_prefetch, filename_offset, filename_length,
/// flags)` from one fixed-size metric entry. `trace_index`/`trace_size` come back pre-widened to
/// `usize` since that's what [`TracesForDependencyFn`] takes; `blocks_to_prefetch` stays `u32`
/// since it's stored as-is on [`Metric`].
type EntryFieldsFn = fn(&[u8]) -> (usize, usize, u32, u32, u32, u32);

/// v23/v26/v30 metric entry layout: 32-byte stride
/// (`trace_index`:u32, `trace_size`:u32, `blocks_to_prefetch`:u32, `filename_offset`:u32,
/// `filename_length`:u32, `flags`:u32, +8 reserved). See [`entry_fields_20_stride`] for the older
/// 20-byte-stride layout. See `AGENTS.md` for the overall per-version module convention.
fn entry_fields_32_stride(entry: &[u8]) -> (usize, usize, u32, u32, u32, u32) {
    let trace_index = u32_at_pos(entry, 0) as usize;
    let trace_size = u32_at_pos(entry, 4) as usize;
    let blocks_to_prefetch = u32_at_pos(entry, 8);
    let filename_offset = u32_at_pos(entry, 12);
    let filename_length = u32_at_pos(entry, 16);
    let flags = u32_at_pos(entry, 20);
    (
        trace_index,
        trace_size,
        blocks_to_prefetch,
        filename_offset,
        filename_length,
        flags,
    )
}

/// v17 metric entry layout: 20-byte stride (`trace_index`:u32, `trace_size`:u32,
/// `filename_offset`:u32, `filename_length`:u32, `flags`:u32). Unlike later versions there is no
/// separate `blocks_to_prefetch` field — `trace_size` doubles as it.
fn entry_fields_20_stride(entry: &[u8]) -> (usize, usize, u32, u32, u32, u32) {
    let trace_index = u32_at_pos(entry, 0) as usize;
    let trace_size = u32_at_pos(entry, 4);
    let filename_offset = u32_at_pos(entry, 8);
    let filename_length = u32_at_pos(entry, 12);
    let flags = u32_at_pos(entry, 16);
    (
        trace_index,
        trace_size as usize,
        trace_size,
        filename_offset,
        filename_length,
        flags,
    )
}

fn metrics_array_stride(
    file_buffer: &[u8],
    info: &PrefetchFileInformation,
    stride: u32,
    extract_fields: EntryFieldsFn,
    traces_for_dependency: TracesForDependencyFn,
) -> ForensicResult<Vec<Metric>> {
    let strings_array = &file_buffer[checked_range(
        info.filename_string_offset,
        info.filename_string_size,
        file_buffer.len(),
        "filename strings array",
    )?];
    let metric_array = &file_buffer[checked_range(
        info.metrics_offsets,
        info.metrics_count.saturating_mul(stride),
        file_buffer.len(),
        "metrics array",
    )?];
    let mut metrics = Vec::with_capacity(info.metrics_count as usize);
    for entry in metric_array.chunks(stride as usize) {
        let (trace_index, trace_size, blocks_to_prefetch, filename_offset, filename_length, flags) =
            extract_fields(entry);
        let file = utf16_at_offset(
            strings_array,
            filename_offset as usize,
            filename_length as usize,
        )?;
        let metric = Metric {
            file,
            flags: flags.into(),
            traces: traces_for_dependency(file_buffer, info, trace_index, trace_size)?,
            blocks_to_prefetch,
        };
        check_anomaly_in_metrics(&metric);
        metrics.push(metric);
    }
    Ok(metrics)
}

pub fn metrics_array_23(
    file_buffer: &[u8],
    info: &PrefetchFileInformation,
) -> ForensicResult<Vec<Metric>> {
    metrics_array_stride(
        file_buffer,
        info,
        32,
        entry_fields_32_stride,
        traces_for_dependency_v17,
    )
}

pub fn metrics_array_17(
    file_buffer: &[u8],
    info: &PrefetchFileInformation,
) -> ForensicResult<Vec<Metric>> {
    metrics_array_stride(
        file_buffer,
        info,
        20,
        entry_fields_20_stride,
        traces_for_dependency_v17,
    )
}

pub fn metrics_array_26(
    buffer: &[u8],
    info: &PrefetchFileInformation,
) -> ForensicResult<Vec<Metric>> {
    metrics_array_23(buffer, info)
}

pub fn metrics_array_30(
    file_buffer: &[u8],
    info: &PrefetchFileInformation,
) -> ForensicResult<Vec<Metric>> {
    metrics_array_stride(
        file_buffer,
        info,
        32,
        entry_fields_32_stride,
        traces_for_dependency_v30,
    )
}

fn check_anomaly_in_metrics(metric: &Metric) {
    if is_resource(&metric.file) {
        // ICON
        if metric.has_executable_block() {
            forensic_rs::warn!(
                "The loaded file {} should not have executable blocks",
                metric.file
            );
        }
    }
}

fn is_resource(file: &str) -> bool {
    file.ends_with(".NLS") || file.ends_with(".RES")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info_with_strings(
        metrics_offsets: u32,
        metrics_count: u32,
        filename_string_offset: u32,
        filename_string_size: u32,
    ) -> PrefetchFileInformation {
        PrefetchFileInformation {
            metrics_offsets,
            metrics_count,
            filename_string_offset,
            filename_string_size,
            ..Default::default()
        }
    }

    #[test]
    fn metrics_array_17_decodes_single_entry() {
        // strings array: "A" + NUL (4 bytes)
        let strings = [0x41, 0x00, 0x00, 0x00];
        // entry (20 bytes): trace_index@0, trace_size@4, filename_offset@8=0,
        // filename_length@12=4, flags@16
        let mut entry = [0u8; 20];
        entry[12..16].copy_from_slice(&4u32.to_le_bytes());
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&strings); // filename_string_offset = 0, size = 4
        buffer.extend_from_slice(&entry); // metrics_offsets = 4
        let info = info_with_strings(4, 1, 0, 4);
        let metrics = metrics_array_17(&buffer, &info).unwrap();
        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0].file, "A");
    }

    #[test]
    fn metrics_array_17_rejects_metrics_offsets_past_buffer() {
        let info = info_with_strings(1000, 1, 0, 0);
        let buffer = vec![0u8; 20];
        assert!(metrics_array_17(&buffer, &info).is_err());
    }

    #[test]
    fn metrics_array_23_rejects_metrics_count_overflowing_u32_instead_of_panicking() {
        // metrics_count * 32 would overflow u32 if computed naively
        let info = info_with_strings(0, u32::MAX, 0, 0);
        let buffer = vec![0u8; 32];
        assert!(metrics_array_23(&buffer, &info).is_err());
    }

    #[test]
    fn metrics_array_23_rejects_filename_length_past_strings_array() {
        let mut buffer = vec![0u8; 32]; // one 32-byte metric entry, empty strings array
        buffer[12..16].copy_from_slice(&0u32.to_le_bytes()); // filename_offset = 0
        buffer[16..20].copy_from_slice(&u32::MAX.to_le_bytes()); // filename_length, absurd
        let info = info_with_strings(0, 1, 0, 0);
        assert!(metrics_array_23(&buffer, &info).is_err());
    }

    #[test]
    fn metrics_array_26_decodes_single_entry() {
        // strings array: "A" + NUL (4 bytes)
        let strings = [0x41, 0x00, 0x00, 0x00];
        // entry (32 bytes): trace_index@0, trace_size@4, blocks_to_prefetch@8,
        // filename_offset@12=0, filename_length@16=4, flags@20
        let mut entry = [0u8; 32];
        entry[8..12].copy_from_slice(&7u32.to_le_bytes());
        entry[16..20].copy_from_slice(&4u32.to_le_bytes());
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&strings);
        buffer.extend_from_slice(&entry);
        let info = info_with_strings(4, 1, 0, 4);
        let metrics = metrics_array_26(&buffer, &info).unwrap();
        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0].file, "A");
        assert_eq!(metrics[0].blocks_to_prefetch, 7);
        assert!(metrics[0].traces.is_empty());
    }

    #[test]
    fn metrics_array_26_rejects_metrics_count_overflowing_u32_instead_of_panicking() {
        let info = info_with_strings(0, u32::MAX, 0, 0);
        let buffer = vec![0u8; 32];
        assert!(metrics_array_26(&buffer, &info).is_err());
    }

    #[test]
    fn metrics_array_30_decodes_single_entry() {
        let strings = [0x41, 0x00, 0x00, 0x00];
        let mut entry = [0u8; 32];
        entry[8..12].copy_from_slice(&9u32.to_le_bytes());
        entry[16..20].copy_from_slice(&4u32.to_le_bytes());
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&strings);
        buffer.extend_from_slice(&entry);
        let info = info_with_strings(4, 1, 0, 4);
        let metrics = metrics_array_30(&buffer, &info).unwrap();
        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0].file, "A");
        assert_eq!(metrics[0].blocks_to_prefetch, 9);
        assert!(metrics[0].traces.is_empty());
    }

    #[test]
    fn metrics_array_30_rejects_filename_length_past_strings_array() {
        let mut buffer = vec![0u8; 32]; // one 32-byte metric entry, empty strings array
        buffer[16..20].copy_from_slice(&u32::MAX.to_le_bytes()); // filename_length, absurd
        let info = info_with_strings(0, 1, 0, 0);
        assert!(metrics_array_30(&buffer, &info).is_err());
    }
}
