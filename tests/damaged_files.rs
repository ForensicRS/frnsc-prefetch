//! Damaged and crafted prefetch files must be errors: no panic, no endless loop, and no
//! allocation larger than the size limit, whatever the counts and sizes in the file claim.
//!
//! Ported from the ys-prefetch-parser fork's `tests/test_damaged_files.rs` (Yamato Security,
//! commit 1b5a5fb, MIT), run over the forensic-testenv prefetch samples. Samples that aren't
//! fetched are skipped (`forensic-testenv/tools/fetch.py --crate frnsc-prefetch`).

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::BTreeMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use frnsc_prefetch::decompress::{decompress_bounded, CompressionAlgorithm};
use frnsc_prefetch::prelude::*;

/// Records the largest allocation request.
struct Tracking;
static LARGEST: AtomicUsize = AtomicUsize::new(0);
unsafe impl GlobalAlloc for Tracking {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        LARGEST.fetch_max(layout.size(), Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        LARGEST.fetch_max(new_size, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}
#[global_allocator]
static TRACKING: Tracking = Tracking;

/// `PREFETCH_DECOMPRESSED_SIZE_LIMIT` in `src/prefetch.rs`.
const SIZE_LIMIT: usize = 64_000_000;

/// The valid testenv samples small enough to damage many times over.
const SAMPLES: &[&str] = &[
    "prefetch-v17-xp-cmd",
    "prefetch-v23-vista-cmd",
    "prefetch-v23-win7-calc",
    "prefetch-v26-win8-calc",
    "prefetch-v26-taskhost",
    "prefetch-v30-mam-win10-calc",
    "prefetch-v30-mam-notepad",
    "prefetch-v31-mam-win11",
    "prefetch-artemis-win7-verclsid",
    "prefetch-artemis-win7-mscorsvw",
    "prefetch-artemis-win10-am-delta-patch",
    "prefetch-artemis-win11-7z",
];

fn samples() -> Vec<(&'static str, Vec<u8>)> {
    SAMPLES
        .iter()
        .filter_map(|id| forensic_testdata::artifact(id).map(|p| (*id, std::fs::read(p).unwrap())))
        .collect()
}

/// The uncompressed SCCA data of a sample, so that damage reaches the structures rather than
/// only the compressed stream.
fn payload(data: &[u8]) -> Vec<u8> {
    if !data.starts_with(b"MAM") {
        return data.to_vec();
    }
    let signature = u32::from_le_bytes(data[0..4].try_into().unwrap());
    let size = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;
    let algorithm = CompressionAlgorithm::from((signature >> 24) & 0x0F);
    let start = if signature >> 28 > 0 { 12 } else { 8 };
    let mut out = Vec::new();
    decompress_bounded(&data[start..], &mut out, algorithm, size).unwrap();
    out
}

/// xorshift64: deterministic damage.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

static LOCATION: Mutex<String> = Mutex::new(String::new());

/// Parses damaged inputs and groups the panics by location.
struct Checker {
    panics: BTreeMap<String, usize>,
    parsed: usize,
}

impl Checker {
    fn new() -> Self {
        std::panic::set_hook(Box::new(|info| {
            if let Some(l) = info.location() {
                *LOCATION.lock().unwrap() = format!("{}:{}", l.file(), l.line());
            }
        }));
        Self {
            panics: BTreeMap::new(),
            parsed: 0,
        }
    }

    fn check(&mut self, data: &[u8]) {
        self.parsed += 1;
        let parse = AssertUnwindSafe(|| {
            // Only panics and allocations matter here: an Err is the right outcome for most.
            let _result = read_prefetch_bytes("X.EXE-00000000.pf", data);
        });
        if catch_unwind(parse).is_err() {
            let location = LOCATION.lock().unwrap().clone();
            *self.panics.entry(location).or_insert(0) += 1;
        }
    }

    fn assert_clean(self) {
        let _hook = std::panic::take_hook();
        assert!(self.panics.is_empty(), "panics: {:?}", self.panics);
        let largest = LARGEST.load(Ordering::Relaxed);
        assert!(largest <= SIZE_LIMIT, "largest allocation {largest}");
    }
}

// One test, so the panic hook isn't shared with tests on other threads.
#[test]
fn damaged_and_crafted_files_are_errors() {
    let samples = samples();
    let mut checker = Checker::new();

    // Random damage: overwritten bytes, sometimes a truncation, to both the file as stored and
    // its uncompressed data.
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for (_, data) in &samples {
        for original in [data.clone(), payload(data)] {
            for i in 0..100 {
                let mut d = original.clone();
                for _ in 0..1 + rng.next() % 8 {
                    let pos = rng.next() as usize % d.len();
                    d[pos] = match i % 3 {
                        0 => rng.next() as u8,
                        1 => 0xFF,
                        _ => 0x00,
                    };
                }
                if i % 7 == 0 {
                    d.truncate(rng.next() as usize % d.len());
                }
                checker.check(&d);
            }
        }
    }

    // Every byte of the header and file information (which hold every offset, count and size)
    // at its extremes.
    for (_, data) in &samples {
        let original = payload(data);
        for pos in 0..original.len().min(308) {
            for value in [0x00, 0xFF, 0x7F, 0x80] {
                let mut d = original.clone();
                d[pos] = value;
                checker.check(&d);
            }
        }
    }

    // A compressed header announcing 4 GiB.
    let mut mam = b"MAM\x04\xff\xff\xff\xff".to_vec();
    mam.extend_from_slice(&[0u8; 300]);
    assert!(read_prefetch_bytes("X.EXE-00000000.pf", &mam).is_err());

    // A version 30 file whose every count and size is 0xFFFFFFFF.
    let mut scca = vec![0u8; 400];
    scca[0..4].copy_from_slice(&30u32.to_le_bytes());
    scca[4..8].copy_from_slice(b"SCCA");
    for field in (84 + 4..84 + 36).step_by(4) {
        scca[field..field + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    }
    assert!(read_prefetch_bytes("X.EXE-00000000.pf", &scca).is_err());

    eprintln!(
        "{} damaged files from {} samples",
        checker.parsed,
        samples.len()
    );
    checker.assert_clean();
}
