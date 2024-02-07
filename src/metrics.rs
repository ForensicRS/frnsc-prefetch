use forensic_rs::{
    err::{ForensicError, ForensicResult},
    notifications::NotificationType,
};

use crate::{
    common::{u32_at_pos, Metric, PrefetchFileInformation},
    trace::{traces_for_dependency_v17, traces_for_dependency_v30},
};

pub fn metrics_array_23(
    file_buffer: &[u8],
    info: &PrefetchFileInformation,
) -> ForensicResult<Vec<Metric>> {
    let end_string_pos = (info.filename_string_offset + info.filename_string_size) as usize;
    if end_string_pos > file_buffer.len() || info.metrics_offsets as usize > file_buffer.len() {
        return Err(ForensicError::bad_format_str(
            "The metrics array position is greater than the file buffer length",
        ));
    }
    let strings_array = &file_buffer[info.filename_string_offset as usize..end_string_pos];
    let metric_array = &file_buffer[info.metrics_offsets as usize..];
    let mut metrics = Vec::with_capacity(info.metrics_count as usize);
    for i in 0..info.metrics_count as usize {
        let entry: &[u8] = &metric_array[i * 32..(i + 1) * 32];
        let trace_index = u32_at_pos(entry, 0) as usize;
        let trace_size = u32_at_pos(entry, 4) as usize;
        let blocks_to_prefetch = u32_at_pos(entry, 8);
        let filename_offset = u32_at_pos(entry, 12) as usize;
        let filename_length = u32_at_pos(entry, 16) as usize;
        let flags = u32_at_pos(entry, 20);
        let filename = &strings_array[filename_offset..filename_offset + filename_length];
        let name_buffer: &[u16] = unsafe { std::mem::transmute(filename) };
        let end = name_buffer
            .iter()
            .position(|&v| v == 0)
            .unwrap_or(name_buffer.len());
        let file = String::from_utf16_lossy(&name_buffer[0..end]);
        let metric = Metric {
            file,
            flags: flags.into(),
            traces: traces_for_dependency_v17(file_buffer, info, trace_index, trace_size)?,
            blocks_to_prefetch,
        };
        check_anomaly_in_metrics(&metric);
        metrics.push(metric);
    }
    Ok(metrics)
}

pub fn metrics_array_17(
    file_buffer: &[u8],
    info: &PrefetchFileInformation,
) -> ForensicResult<Vec<Metric>> {
    let end_string_pos = (info.filename_string_offset + info.filename_string_size) as usize;
    if end_string_pos > file_buffer.len() || (info.metrics_offsets + info.metrics_count * 20) as usize > file_buffer.len() {
        return Err(ForensicError::bad_format_str(
            "The metrics array position is greater than the file buffer",
        ));
    }
    let strings_array = &file_buffer[info.filename_string_offset as usize..end_string_pos];
    let metric_array = &file_buffer[info.metrics_offsets as usize..];
    let mut metrics = Vec::with_capacity(info.metrics_count as usize);
    for i in 0..info.metrics_count as usize {
        let entry: &[u8] = &metric_array[i * 20..(i + 1) * 20];
        let trace_index = u32_at_pos(entry, 0) as usize;
        let trace_size = u32_at_pos(entry, 4);
        let filename_offset = u32_at_pos(entry, 8) as usize;
        let filename_length = u32_at_pos(entry, 12) as usize;
        let flags = u32_at_pos(entry, 16);
        let filename = &strings_array[filename_offset..filename_offset + filename_length];
        let name_buffer: &[u16] = unsafe { std::mem::transmute(filename) };
        let end = name_buffer
            .iter()
            .position(|&v| v == 0)
            .unwrap_or(name_buffer.len());
        let file = String::from_utf16_lossy(&name_buffer[0..end]);
        let metric = Metric {
            file,
            flags: flags.into(),
            traces: traces_for_dependency_v17(file_buffer, info, trace_index, trace_size as usize)?,
            blocks_to_prefetch: trace_size,
        };
        check_anomaly_in_metrics(&metric);
        metrics.push(metric);
    }
    Ok(metrics)
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
    let end_string_pos = (info.filename_string_offset + info.filename_string_size) as usize;
    if end_string_pos > file_buffer.len() || info.metrics_offsets as usize > file_buffer.len() {
        return Err(ForensicError::bad_format_str(
            "The metrics array position is greater than the file buffer length",
        ));
    }
    let strings_array = &file_buffer[info.filename_string_offset as usize..end_string_pos];
    let metric_array = &file_buffer[info.metrics_offsets as usize..];
    let mut metrics = Vec::with_capacity(info.metrics_count as usize);
    for i in 0..info.metrics_count as usize {
        let entry: &[u8] = &metric_array[i * 32..(i + 1) * 32];
        let trace_index = u32_at_pos(entry, 0) as usize;
        let trace_size = u32_at_pos(entry, 4) as usize;
        let blocks_to_prefetch = u32_at_pos(entry, 8);
        let filename_offset = u32_at_pos(entry, 12) as usize;
        let filename_length = u32_at_pos(entry, 16) as usize;
        let flags = u32_at_pos(entry, 20);
        let filename = &strings_array[filename_offset..filename_offset + filename_length];
        let name_buffer: &[u16] = unsafe { std::mem::transmute(filename) };
        let end = name_buffer
            .iter()
            .position(|&v| v == 0)
            .unwrap_or(name_buffer.len());
        let file = String::from_utf16_lossy(&name_buffer[0..end]);
        let metric = Metric {
            file,
            flags: flags.into(),
            traces: traces_for_dependency_v30(file_buffer, info, trace_index, trace_size)?,
            blocks_to_prefetch,
        };
        check_anomaly_in_metrics(&metric);
        metrics.push(metric);
    }
    Ok(metrics)
}

fn check_anomaly_in_metrics(metric: &Metric) {
    if is_resource(&metric.file) {
        // ICON
        if metric.has_executable_block() {
            forensic_rs::notify_info!(
                NotificationType::SuspiciousArtifact,
                "The loaded file {} should not have executable blocks",
                metric.file
            );
            println!("{:?}", metric.file);
            //panic!("The loaded file {} should not have executable blocks", metric.file);
        }
    }
}

fn is_resource(file: &str) -> bool {
    if file.ends_with(".NLS") || file.ends_with(".RES") {
        return true;
    }
    false
}
