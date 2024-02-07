use std::path::Path;

use forensic_rs::{
    core::fs::{ChRootFileSystem, StdVirtualFS},
    traits::vfs::VirtualFileSystem,
};

use crate::prefetch::{
    read_prefetch_file_compressed, read_prefetch_file_no_compressed, read_prefetch_form_fs,
};

#[test]
fn should_parse_all_prefetchs_from_fs() {
    let mut fs = ChRootFileSystem::new("./artifacts/17", Box::new(StdVirtualFS::new()));
    read_prefetch_form_fs(&mut fs).expect("Must read all prefetch from filesystem");
}

#[test]
fn should_parse_prefetch_v17() {
    let mut fs = StdVirtualFS::new();
    let file = fs
        .open(Path::new(
            "./artifacts/17/C/Windows/Prefetch/CMD.EXE-087B4001.pf",
        ))
        .unwrap();
    read_prefetch_file_no_compressed("CMD.EXE-087B4001.pf", file).unwrap();
}
#[test]
fn should_parse_prefetch_v30_2() {
    let mut fs = StdVirtualFS::new();
    let file = fs
        .open(Path::new(
            "./artifacts/30/C/Windows/Prefetch/RUST_OUT.EXE-5D2C8541.pf",
        ))
        .unwrap();
    read_prefetch_file_compressed("RUST_OUT.EXE-5D2C8541.pf", file).unwrap();
}
#[test]
fn should_parse_prefetch_v30() {
    let mut fs = StdVirtualFS::new();
    let file = fs
        .open(Path::new(
            "./artifacts/30/C/Windows/Prefetch/CMD.EXE-D269B812.pf",
        ))
        .unwrap();
    read_prefetch_file_compressed("CMD.EXE-D269B812.pf", file).unwrap();
}

#[test]
fn should_parse_prefetch_v26() {
    let mut fs = StdVirtualFS::new();
    let file = fs
        .open(Path::new(
            "./artifacts/26/C/Windows/Prefetch/CMD.EXE-4A81B364.pf",
        ))
        .unwrap();
    read_prefetch_file_no_compressed("CMD.EXE-4A81B364.pf", file).unwrap();
}

#[test]
fn should_parse_prefetch_v23() {
    let mut fs = StdVirtualFS::new();
    let file = fs
        .open(Path::new(
            "./artifacts/23/C/Windows/Prefetch/NOTEPAD.EXE-D8414F97.pf",
        ))
        .unwrap();
    read_prefetch_file_no_compressed("NOTEPAD.EXE-D8414F97.pf", file).unwrap();
}

#[test]
fn should_parse_prefetch_v30_powershell() {
    let mut fs = StdVirtualFS::new();
    let file = fs
        .open(Path::new(
            "./artifacts/30/C/Windows/Prefetch/POWERSHELL.EXE-AE8EDC9B.pf",
        ))
        .unwrap();
    let pref = read_prefetch_file_compressed("POWERSHELL.EXE-AE8EDC9B.pf", file).unwrap();
    println!("{:?}", pref);
}

#[test]
fn should_parse_prefetch_v30_cmd() {
    let mut fs = StdVirtualFS::new();
    let file = fs
        .open(Path::new(
            "./artifacts/30/C/Windows/Prefetch/CMD.EXE-6D6290C5.pf",
        ))
        .unwrap();
    let pref = read_prefetch_file_compressed("CMD.EXE-6D6290C5.pf", file).unwrap();
    //println!("{:?}", pref);
    assert_eq!(4, pref.run_count);
    assert_eq!(4, pref.last_run_times.len());
    assert_eq!(133515874611440142, pref.last_run_times[0]); // 5 February 2024 6:17:41
    assert_eq!(133515874591645855, pref.last_run_times[1]); // 5 February 2024 6:17:39
    assert_eq!(133515561632524658, pref.last_run_times[2]); // 4 February 2024 21:36:03
    assert_eq!(133514937170602624, pref.last_run_times[3]); // 4 February 2024 4:15:17
}

#[test]
#[ignore]
fn should_parse_current_prefetches() {
    let mut fs = StdVirtualFS::new();
    let _pref = read_prefetch_form_fs(&mut fs).expect("Must read all prefetch from filesystem");
    //println!("{:?}", pref);
}
