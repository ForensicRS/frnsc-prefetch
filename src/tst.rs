use forensic_rs::{
    core::{
        fs::{ChRootFileSystem, StdVirtualFS},
        path::FPath,
    },
    traits::{
        forensic::{IntoActivity, IntoTimeline},
        vfs::FileSystem,
    },
    utils::{testing::InMemoryVirtualFileSystem, time::Filetime},
};
use std::sync::Arc;

use crate::prefetch::{
    read_prefetch_file_compressed, read_prefetch_file_no_compressed, read_prefetch_form_fs,
};

#[test]
fn should_parse_all_prefetchs_from_fs() {
    // ChRootFileSystem's root represents the drive itself (drive designators in
    // queried paths are stripped, not honored) — root at the fixture's "C" folder.
    let fs = ChRootFileSystem::new("./artifacts/17/C", Arc::new(StdVirtualFS::new()));
    read_prefetch_form_fs(&fs).expect("Must read all prefetch from filesystem");
}

#[test]
fn should_parse_prefetch_v17() {
    let fs = StdVirtualFS::new();
    let file = fs
        .open(FPath::new(
            "./artifacts/17/C/Windows/Prefetch/CMD.EXE-087B4001.pf",
        ))
        .unwrap();
    let a = read_prefetch_file_no_compressed("CMD.EXE-087B4001.pf", file).unwrap();
    println!("{:?}", a);
}
#[test]
fn should_parse_prefetch_v30_2() {
    let fs = StdVirtualFS::new();
    let file = fs
        .open(FPath::new(
            "./artifacts/30/C/Windows/Prefetch/RUST_OUT.EXE-5D2C8541.pf",
        ))
        .unwrap();
    read_prefetch_file_compressed("RUST_OUT.EXE-5D2C8541.pf", file).unwrap();
}
#[test]
fn should_parse_prefetch_v30() {
    let fs = StdVirtualFS::new();
    let file = fs
        .open(FPath::new(
            "./artifacts/30/C/Windows/Prefetch/CMD.EXE-D269B812.pf",
        ))
        .unwrap();
    read_prefetch_file_compressed("CMD.EXE-D269B812.pf", file).unwrap();
}

#[test]
fn should_parse_prefetch_v26() {
    let fs = StdVirtualFS::new();
    let file = fs
        .open(FPath::new(
            "./artifacts/26/C/Windows/Prefetch/CMD.EXE-4A81B364.pf",
        ))
        .unwrap();
    read_prefetch_file_no_compressed("CMD.EXE-4A81B364.pf", file).unwrap();
}

#[test]
fn should_parse_prefetch_v23() {
    let fs = StdVirtualFS::new();
    let file = fs
        .open(FPath::new(
            "./artifacts/23/C/Windows/Prefetch/NOTEPAD.EXE-D8414F97.pf",
        ))
        .unwrap();
    read_prefetch_file_no_compressed("NOTEPAD.EXE-D8414F97.pf", file).unwrap();
}

#[test]
fn should_parse_prefetch_v30_powershell() {
    let fs = StdVirtualFS::new();
    let file = fs
        .open(FPath::new(
            "./artifacts/30/C/Windows/Prefetch/POWERSHELL.EXE-AE8EDC9B.pf",
        ))
        .unwrap();
    let pref = read_prefetch_file_compressed("POWERSHELL.EXE-AE8EDC9B.pf", file).unwrap();
    let mut forensic_data = pref.timeline();
    let event = forensic_data.next().unwrap().unwrap();
    println!("{:?}", event);
    let mut forensic_data = pref.activity();
    let activity = forensic_data.next().unwrap().unwrap();
    println!("Activity: {:?}", activity);
}

#[test]
fn should_parse_prefetch_v30_cmd() {
    let fs = StdVirtualFS::new();
    let file = fs
        .open(FPath::new(
            "./artifacts/30/C/Windows/Prefetch/CMD.EXE-6D6290C5.pf",
        ))
        .unwrap();
    let pref = read_prefetch_file_compressed("CMD.EXE-6D6290C5.pf", file).unwrap();
    //println!("{:?}", pref);
    assert_eq!(4, pref.run_count);
    assert_eq!(4, pref.last_run_times.len());
    assert_eq!(Filetime::new(133515874611440142), pref.last_run_times[0]); // 5 February 2024 6:17:41
    assert_eq!(Filetime::new(133515874591645855), pref.last_run_times[1]); // 5 February 2024 6:17:39
    assert_eq!(Filetime::new(133515561632524658), pref.last_run_times[2]); // 4 February 2024 21:36:03
    assert_eq!(Filetime::new(133514937170602624), pref.last_run_times[3]); // 4 February 2024 4:15:17
}

#[test]
#[ignore]
fn should_parse_current_prefetches() {
    let fs = StdVirtualFS::new();
    let _pref = read_prefetch_form_fs(&fs).expect("Must read all prefetch from filesystem");
    //println!("{:?}", pref);
}

// Negative-path tests: a forensic parser processes potentially corrupted or adversarial
// evidence, so a malformed file must be rejected with an `Err`, never panic.

fn open_in_memory(bytes: Vec<u8>) -> Box<dyn forensic_rs::traits::vfs::VirtualFile> {
    InMemoryVirtualFileSystem::new()
        .with_file("bad.pf", bytes)
        .open(FPath::new("bad.pf"))
        .unwrap()
}

#[test]
fn rejects_prefetch_header_shorter_than_84_bytes() {
    let file = open_in_memory(vec![0u8; 10]);
    assert!(read_prefetch_file_no_compressed("bad.pf", file).is_err());
}

#[test]
fn rejects_bad_signature() {
    let mut buffer = vec![0u8; 84];
    buffer[0..4].copy_from_slice(&17u32.to_le_bytes());
    buffer[4..8].copy_from_slice(b"XXXX");
    let file = open_in_memory(buffer);
    assert!(read_prefetch_file_no_compressed("bad.pf", file).is_err());
}

#[test]
fn rejects_unknown_version() {
    let mut buffer = vec![0u8; 84];
    buffer[0..4].copy_from_slice(&99u32.to_le_bytes());
    buffer[4..8].copy_from_slice(b"SCCA");
    let file = open_in_memory(buffer);
    assert!(read_prefetch_file_no_compressed("bad.pf", file).is_err());
}

#[test]
fn rejects_corrupted_huge_offsets_without_panicking() {
    // Valid v17 header/signature, but the version-specific info starting at byte 84
    // (metrics_offsets/metrics_count) is corrupted to an absurd value that would
    // previously overflow u32 arithmetic during bounds-checking.
    let mut buffer = vec![0u8; 200];
    buffer[0..4].copy_from_slice(&17u32.to_le_bytes());
    buffer[4..8].copy_from_slice(b"SCCA");
    buffer[84..88].copy_from_slice(&u32::MAX.to_le_bytes()); // metrics_offsets
    buffer[88..92].copy_from_slice(&u32::MAX.to_le_bytes()); // metrics_count
    let file = open_in_memory(buffer);
    assert!(read_prefetch_file_no_compressed("bad.pf", file).is_err());
}
