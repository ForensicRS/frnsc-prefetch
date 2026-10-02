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
    assert_eq!(
        activity.origin,
        forensic_rs::artifact::Artifact::Windows(forensic_rs::artifact::WindowsArtifacts::Prefetch)
    );
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

fn fixture(path: &str) -> Vec<u8> {
    std::fs::read(format!("./artifacts/{path}")).unwrap()
}

#[test]
fn every_fixture_parses_without_anomalies() {
    // The hash in the file name is hexadecimal: parsed as decimal, it used to "mismatch" on
    // almost every file.
    for (path, name) in [
        (
            "17/C/Windows/Prefetch/CMD.EXE-087B4001.pf",
            "CMD.EXE-087B4001.pf",
        ),
        (
            "23/C/Windows/Prefetch/NOTEPAD.EXE-D8414F97.pf",
            "NOTEPAD.EXE-D8414F97.pf",
        ),
        (
            "26/C/Windows/Prefetch/CMD.EXE-4A81B364.pf",
            "CMD.EXE-4A81B364.pf",
        ),
        (
            "30/C/Windows/Prefetch/CMD.EXE-6D6290C5.pf",
            "CMD.EXE-6D6290C5.pf",
        ),
        (
            "30/C/Windows/Prefetch/POWERSHELL.EXE-AE8EDC9B.pf",
            "POWERSHELL.EXE-AE8EDC9B.pf",
        ),
    ] {
        let pf = crate::prefetch::read_prefetch_file(name, open_in_memory(fixture(path))).unwrap();
        assert!(pf.anomalies.is_empty(), "{name}: {:?}", pf.anomalies);
    }
}

#[test]
fn a_renamed_or_unnamed_file_is_an_anomaly_not_an_error() {
    use crate::anomaly::PrefetchAnomaly;
    let bytes = fixture("17/C/Windows/Prefetch/CMD.EXE-087B4001.pf");
    let pf = crate::prefetch::read_prefetch_file(
        "EVIL-TOOL.EXE-087B4001.pf",
        open_in_memory(bytes.clone()),
    )
    .unwrap();
    assert_eq!(
        pf.anomalies,
        vec![PrefetchAnomaly::NameMismatch {
            file_name: "EVIL-TOOL.EXE".into(),
            embedded: "CMD.EXE".into(),
        }]
    );
    let pf =
        crate::prefetch::read_prefetch_file("CMD.EXE-DEADBEEF.pf", open_in_memory(bytes.clone()))
            .unwrap();
    assert!(matches!(
        pf.anomalies.as_slice(),
        [PrefetchAnomaly::HashMismatch {
            file_name: 0xDEAD_BEEF,
            embedded: 0x087B_4001
        }]
    ));
    let pf = crate::prefetch::read_prefetch_file("cmd.pf", open_in_memory(bytes)).unwrap();
    assert!(matches!(
        pf.anomalies.as_slice(),
        [PrefetchAnomaly::NoHashInName { .. }]
    ));
}

/// A MAM file rebuilt with the CRC flag and a CRC slot (`MAM\x84`), the stored CRC being `crc`
/// or, when `None`, the right one.
fn with_crc(mam: &[u8], crc: Option<u32>) -> Vec<u8> {
    let mut header = mam[0..8].to_vec();
    header[3] |= 0x80;
    let data = &mam[8..];
    let mut hash = crc32fast::Hasher::new();
    hash.update(&header);
    hash.update(&[0, 0, 0, 0]);
    hash.update(data);
    let crc = crc.unwrap_or_else(|| hash.finalize());
    let mut out = header;
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(data);
    out
}

#[test]
fn a_crc_mismatch_is_kept_and_the_file_still_parses() {
    use crate::anomaly::PrefetchAnomaly;
    use forensic_rs::provenance::AnomalyFlags;
    let mam = fixture("30/C/Windows/Prefetch/RUST_OUT.EXE-5D2C8541.pf");
    let name = "RUST_OUT.EXE-5D2C8541.pf";
    let good = read_prefetch_file_compressed(name, open_in_memory(with_crc(&mam, None))).unwrap();
    assert!(good.anomalies.is_empty(), "{:?}", good.anomalies);

    let bad = read_prefetch_file_compressed(name, open_in_memory(with_crc(&mam, Some(1)))).unwrap();
    assert_eq!(bad.name, good.name);
    assert_eq!(bad.run_count, good.run_count);
    assert!(matches!(
        bad.anomalies.as_slice(),
        [PrefetchAnomaly::CrcMismatch { stored: 1, .. }]
    ));
    assert_eq!(
        bad.anomalies[0].flag(),
        Some(AnomalyFlags::CHECKSUM_MISMATCH)
    );
}

#[test]
fn a_truncated_mam_header_is_an_error_not_a_panic() {
    assert!(
        read_prefetch_file_compressed("x.pf", open_in_memory(b"MAM\x04\x10\0\0\0".to_vec()))
            .is_err()
    );
}
