//! [`PrefetchParserFactory`]: prefetch files as pipeline records, one per recorded run.

use forensic_rs::core::fs::walk::WalkOptions;
use forensic_rs::dictionary;
use forensic_rs::prelude::*;

use crate::common::PrefetchFile;
use crate::prefetch::read_prefetch_file;

/// Where Windows keeps prefetch files.
const PREFETCH_DIR: &str = r"C:\Windows\Prefetch";
/// How deep to search when that folder is absent: enough for `<collection>/<host>/.../prefetch/`.
const MAX_DEPTH: u32 = 8;

/// Emits one [`ForensicData`] per run time a prefetch file records (up to 8 on Windows 8+, 1
/// before), with `@timestamp` = that run, which is the event itself. A file with no run time yields
/// one record without a timestamp.
///
/// Files come from `C:\Windows\Prefetch`, or, when that folder is absent (a triage collection),
/// from every `*.pf` found by name. A file that can't be read is one `Err` item; the others go on.
/// Contradictions inside a file ([`crate::anomaly::PrefetchAnomaly`]) are carried on each of its
/// records: `CrcMismatch` as the core `CHECKSUM_MISMATCH` anomaly, every kind by name in
/// `prefetch.anomalies`.
pub struct PrefetchParserFactory {
    descriptor: ParserDescriptor,
}

impl Default for PrefetchParserFactory {
    fn default() -> Self {
        Self {
            descriptor: ParserDescriptor::new(
                "windows.prefetch",
                "Prefetch",
                "Windows Prefetch (.pf) files: executable, run count and last run times",
                env!("CARGO_PKG_VERSION"),
            )
            .with_artifacts(vec![Artifact::Windows(WindowsArtifacts::Prefetch)]),
        }
    }
}

impl PrefetchParserFactory {
    pub fn new() -> Self {
        Self::default()
    }
}

/// The prefetch files on `fs`, sorted, plus the errors met while listing them.
fn locate(fs: &dyn FileSystem) -> (Vec<FPathBuf>, Vec<ForensicError>) {
    let mut paths = Vec::new();
    let mut errors = Vec::new();
    if let Ok(entries) = fs.read_dir(FPath::new(PREFETCH_DIR)) {
        for entry in entries {
            match entry {
                Ok(e) if e.file_type == VFileType::File && is_pf(e.path.as_path()) => {
                    paths.push(e.path)
                }
                Ok(_) => {}
                Err(e) => errors.push(e),
            }
        }
        if !paths.is_empty() {
            paths.sort();
            return (paths, errors);
        }
    }
    let opts = WalkOptions::default()
        .with_max_depth(Some(MAX_DEPTH))
        .with_skip_errors(false);
    for item in fs.walk(FPath::new(""), &opts) {
        match item {
            Ok(e) if e.file_type == VFileType::File && is_pf(e.path.as_path()) => {
                paths.push(e.path)
            }
            Ok(_) => {}
            Err(e) => errors.push(e),
        }
    }
    paths.sort();
    (paths, errors)
}

fn is_pf(path: &FPath) -> bool {
    path.file_name()
        .is_some_and(|n| n.to_ascii_lowercase().ends_with(".pf"))
}

impl ArtifactParserFactory for PrefetchParserFactory {
    fn descriptor(&self) -> &ParserDescriptor {
        &self.descriptor
    }

    fn can_parse(&self, ctx: &ParseContext<'_>) -> bool {
        ctx.vfs()
            .is_some_and(|fs| !locate(fs.as_ref()).0.is_empty())
    }

    fn open(&self, ctx: &ParseContext<'_>) -> ForensicResult<ParserRun> {
        let fs = ctx.vfs().ok_or_else(|| {
            ForensicError::missing_data(
                "FileSystem source required",
                CompactString::const_new("PrefetchParserFactory"),
            )
        })?;
        let (paths, errors) = locate(fs.as_ref());
        let host = ctx.host().to_string();
        let acquisition = ctx.acquisition();
        let mut out: Vec<ForensicResult<ForensicData>> = errors.into_iter().map(Err).collect();
        for path in paths {
            let name = path.as_path().file_name().unwrap_or_default().to_string();
            let parsed = fs
                .open(path.as_path())
                .and_then(|file| read_prefetch_file(&name, file))
                .map_err(|e| e.with_path(path.clone()));
            match parsed {
                Ok(pf) => {
                    let source = ctx.register_source(SourceKey::Path(path.to_string()));
                    out.extend(
                        records(&host, &path, &pf, || {
                            source.mint(acquisition, Recovery::Allocated)
                        })
                        .into_iter()
                        .map(Ok),
                    );
                }
                Err(e) => out.push(Err(e)),
            }
        }
        Ok(ParserRun::pull(out.into_iter()))
    }
}

/// One record per non-zero run time (a zero slot is unset, not a run in 1601).
fn records(
    host: &str,
    path: &FPathBuf,
    pf: &PrefetchFile,
    mut mint: impl FnMut() -> ProvenanceId,
) -> Vec<ForensicData> {
    let runs: Vec<Option<ForensicTimestamp>> = {
        let set: Vec<_> = pf
            .last_run_times
            .iter()
            .filter(|t| t.filetime() != 0)
            .map(|t| Some(ForensicTimestamp::from(*t)))
            .collect();
        if set.is_empty() {
            vec![None]
        } else {
            set
        }
    };
    let names: Vec<Text> = pf
        .anomalies
        .iter()
        .map(|a| Text::Borrowed(a.name()))
        .collect();
    runs.into_iter()
        .enumerate()
        .map(|(index, run)| {
            let provenance = mint();
            let mut data = ForensicData::new(
                host,
                Artifact::Windows(WindowsArtifacts::Prefetch),
                provenance,
            );
            let mut anomalies = Anomalies::empty();
            for detail in pf.anomalies.iter().filter_map(|a| a.detail()) {
                anomalies.add_detail(detail);
            }
            data.set_parsed(
                dictionary::PROCESS_NAME,
                Parsed::with_anomalies(pf.name.clone(), anomalies, provenance),
            );
            if let Some(ts) = run {
                data.set(dictionary::TIMESTAMP, ts);
                // Run times are stored most recent first.
                data.set("prefetch.run_index", index as u64);
            }
            data.set(dictionary::EVENT_ACTION, "prefetch-run");
            data.set(dictionary::FILE_PATH, path.to_string());
            data.set("prefetch.run_count", u64::from(pf.run_count));
            data.set("prefetch.version", u64::from(pf.version));
            if !names.is_empty() {
                data.insert(
                    Text::Borrowed("prefetch.anomalies"),
                    Field::Array(names.clone()),
                );
            }
            data
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use forensic_rs::dictionary;
    use forensic_rs::prelude::*;
    use forensic_rs::provenance::AnomalyFlags;
    use forensic_rs::utils::testing::{collect_run, InMemoryVirtualFileSystem};

    use super::PrefetchParserFactory;

    fn run(fs: Arc<dyn FileSystem>) -> Vec<ForensicResult<ForensicData>> {
        let sources = TriageSources::builder().vfs(fs).build();
        let triage = TriageContext::new("HOST", "t");
        let cancellation = CancellationToken::new();
        let ctx = ParseContext::new(&sources, &triage, &cancellation);
        let parser = PrefetchParserFactory::new();
        assert!(parser.can_parse(&ctx));
        collect_run(parser.open(&ctx).unwrap()).unwrap()
    }

    fn fixture(path: &str) -> Vec<u8> {
        std::fs::read(format!("./artifacts/{path}")).unwrap()
    }

    #[test]
    fn reads_the_windows_prefetch_folder_one_record_per_run() {
        let fs: Arc<dyn FileSystem> = Arc::new(ChRootFileSystem::new(
            "./artifacts/30/C",
            Arc::new(StdVirtualFS::new()),
        ));
        let records = run(fs);
        assert!(records.iter().all(|r| r.is_ok()), "{records:?}");
        let records: Vec<_> = records.into_iter().map(Result::unwrap).collect();
        // Four v30 files, each with up to 8 run times.
        let files: std::collections::BTreeSet<_> = records
            .iter()
            .filter_map(|r| r.field_as_str(dictionary::FILE_PATH).map(str::to_string))
            .collect();
        assert_eq!(files.len(), 4, "{files:?}");
        assert!(records.len() >= files.len());
        for r in &records {
            assert!(r.field(dictionary::TIMESTAMP).is_some());
            assert!(r.field_as_str(dictionary::PROCESS_NAME).is_some());
            assert!(r.field("prefetch.anomalies").is_none());
        }
    }

    #[test]
    fn a_collection_is_searched_by_name_and_problems_stay_visible() {
        let fs: Arc<dyn FileSystem> = Arc::new(
            InMemoryVirtualFileSystem::new()
                .with_file(
                    "host/CopiedFiles/prefetch/CMD.EXE-087B4001.pf",
                    fixture("17/C/Windows/Prefetch/CMD.EXE-087B4001.pf"),
                )
                // Renamed after the fact: the name no longer matches the file.
                .with_file(
                    "host/CopiedFiles/prefetch/SVCHOST.EXE-087B4001.pf",
                    fixture("17/C/Windows/Prefetch/CMD.EXE-087B4001.pf"),
                )
                .with_file(
                    "host/CopiedFiles/prefetch/BROKEN.EXE-00000000.pf",
                    vec![0u8; 16],
                ),
        );
        let records = run(fs);
        let errors: Vec<_> = records.iter().filter(|r| r.is_err()).collect();
        assert_eq!(errors.len(), 1, "{errors:?}");
        let ok: Vec<_> = records.iter().filter_map(|r| r.as_ref().ok()).collect();
        assert_eq!(ok.len(), 2);
        let renamed = ok
            .iter()
            .find(|r| {
                r.field_as_str(dictionary::FILE_PATH)
                    .is_some_and(|p| p.contains("SVCHOST"))
            })
            .unwrap();
        assert_eq!(
            renamed.field("prefetch.anomalies"),
            Some(&Field::Array(vec![Text::Borrowed("name_mismatch")]))
        );
        // No core bit means "renamed", so none is set.
        assert!(renamed.anomalies().flags().is_empty());
    }

    #[test]
    fn a_crc_mismatch_is_a_core_anomaly_on_the_record() {
        let mam = fixture("30/C/Windows/Prefetch/RUST_OUT.EXE-5D2C8541.pf");
        let mut bad = mam[0..8].to_vec();
        bad[3] |= 0x80; // CRC flag
        bad.extend_from_slice(&1u32.to_le_bytes()); // wrong CRC
        bad.extend_from_slice(&mam[8..]);
        let fs: Arc<dyn FileSystem> = Arc::new(
            InMemoryVirtualFileSystem::new().with_file("pf/RUST_OUT.EXE-5D2C8541.pf", bad),
        );
        let records = run(fs);
        let first = records[0].as_ref().unwrap();
        assert!(first.anomalies().has(AnomalyFlags::CHECKSUM_MISMATCH));
    }
}
