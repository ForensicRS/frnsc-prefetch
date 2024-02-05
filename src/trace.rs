use forensic_rs::err::{ForensicError, ForensicResult};

use crate::common::{u32_at_pos, PrefetchFileInformation, Trace};

pub fn traces_for_dependency_v17(file_buffer : &[u8], info : &PrefetchFileInformation, index : usize, size : usize) -> ForensicResult<Vec<Trace>> {
    let end_pos = (info.trace_chain_offset + info.trace_chain_count * 12) as usize;
    if end_pos > file_buffer.len() {
        return Err(ForensicError::bad_format_str("The trace array position is greater than the file buffer length"))
    }
    let trace_array = &file_buffer[info.trace_chain_offset as usize..end_pos];
    let mut traces = Vec::with_capacity(info.trace_chain_count as usize);
    if (index + size) * 12 > trace_array.len() {
        return Err(ForensicError::bad_format_str("The trace array position is greater than the file buffer length"))
    } 
    for i in 0..size {
        let pos = (index + i) * 12;
        let entry = &trace_array[pos..];
        let block_offset = u32_at_pos(entry, 4);
        let flags = entry[8];
        traces.push(Trace {
            flags : flags.into(),
            block_offset,
            used_bitfield : entry[10],
            prefetched_bitfield : entry[11],
        });
    }
    Ok(traces)
}

pub fn process_trace_chain_v17(file_buffer : &[u8], info : &PrefetchFileInformation) -> ForensicResult<Vec<Trace>> {
    let end_pos = (info.trace_chain_offset + info.trace_chain_count * 12) as usize;
    if end_pos > file_buffer.len() {
        return Err(ForensicError::bad_format_str("The trace array position is greater than the file buffer length"))
    }
    let trace_array = &file_buffer[info.trace_chain_offset as usize..end_pos];
    let mut traces = Vec::with_capacity(info.trace_chain_count as usize);
    for i in 0..(info.trace_chain_count as usize) {
        let pos = i * 12;
        let entry = &trace_array[pos..];
        let block_offset = u32_at_pos(entry, 4);
        let flags = entry[8];
        traces.push(Trace {
            flags : flags.into(),
            block_offset,
            used_bitfield : entry[10],
            prefetched_bitfield : entry[11],
        });
    }
    Ok(traces)
}
pub fn process_trace_chain_v30(file_buffer : &[u8], info : &PrefetchFileInformation) -> ForensicResult<Vec<Trace>> {
    let end_pos = (info.trace_chain_offset + info.trace_chain_count * 8) as usize;
    if end_pos > file_buffer.len() {
        return Err(ForensicError::bad_format_str("The trace array position is greater than the file buffer length"))
    }
    let trace_array = &file_buffer[info.trace_chain_offset as usize..end_pos];
    let mut traces = Vec::with_capacity(info.trace_chain_count as usize);
    for i in 0..(info.trace_chain_count as usize) {
        let pos = i * 8;
        let entry = &trace_array[pos..];
        let block_offset = u32_at_pos(entry, 0);
        let flags = entry[4];
        traces.push(Trace {
            flags : flags.into(),
            block_offset,
            used_bitfield : entry[6],
            prefetched_bitfield : entry[7],
        });
    }
    Ok(traces)
}
pub fn traces_for_dependency_v30(file_buffer : &[u8], info : &PrefetchFileInformation, index : usize, size : usize) -> ForensicResult<Vec<Trace>> {
    let end_pos = (info.trace_chain_offset + info.trace_chain_count * 8) as usize;
    if end_pos > file_buffer.len() {
        return Err(ForensicError::bad_format_str("The trace array position is greater than the file buffer length"))
    }
    let trace_array = &file_buffer[info.trace_chain_offset as usize..end_pos];
    let mut traces = Vec::with_capacity(info.trace_chain_count as usize);
    if (index + size) * 8 > trace_array.len() {
        return Err(ForensicError::bad_format_str("The trace array position is greater than the file buffer length"))
    }
    for i in 0..size {
        let pos = (index + i) * 8;
        let entry = &trace_array[pos..];
        let block_offset = u32_at_pos(entry, 0);
        let flags = entry[4].into();
        traces.push(Trace {
            flags,
            block_offset,
            used_bitfield : entry[6],
            prefetched_bitfield : entry[7],
        });
    }
    Ok(traces)
}