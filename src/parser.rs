//! [`PrefetchParserFactory`]: prefetch files as pipeline records, one per recorded run.

use forensic_rs::core::fs::walk::WalkOptions;
use forensic_rs::dictionary;
use forensic_rs::prelude::*;

use crate::common::PrefetchFile;
use crate::prefetch::read_prefetch_file;

/// The ForensicArtifacts definition of prefetch files, which this parser reads.
pub const DEFINITION: &str = "WindowsPrefetchFiles";
/// Where Windows keeps prefetch files, for a run with no artifact catalog.
const PREFETCH_DIR: &str = r"C:\Windows\Prefetch";
/// How deep to search when that folder is absent: enough for `<collection>/<host>/.../prefetch/`.
const MAX_DEPTH: u32 = 8;

/// Emits one [`ForensicData`] per run time a prefetch file records (up to 8 on Windows 8+, 1
/// before), with `@timestamp` = that run, which is the event itself. A file with no run time yields
/// one record without a timestamp.
///
/// Files are located through the run's artifact catalog ([`DEFINITION`], with
/// [`ParseContext::locate_artifact_files`]): at the definition's location, or, on a collection with
/// its own layout, by its file names (`*.pf`). A run with no catalog falls back to this crate's own
/// search: `C:\Windows\Prefetch`, then every `*.pf` by name. Every record says which way its file
/// was found (`artifact.located_by`), and names the definition when the catalog found it. A file
/// that can't be read is one `Err` item; the others go on.
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
            .with_artifacts(vec![Artifact::Windows(WindowsArtifacts::Prefetch)])
            .with_requirements(vec![Requirement::Artifact(ArtifactRef::from_static(
                DEFINITION,
            ))]),
        }
    }
}

impl PrefetchParserFactory {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Where the prefetch files of this run are, sorted, with how each was found and whether the
/// catalog found it, plus the problems met while looking.
struct Located {
    files: Vec<(FPathBuf, FoundBy)>,
    by_catalog: bool,
    errors: Vec<ForensicError>,
}

/// Through the run's catalog when it has [`DEFINITION`], else with [`locate`].
fn locate_for(ctx: &ParseContext<'_>, fs: &dyn FileSystem) -> ForensicResult<Located> {
    let has_definition = ctx
        .sources()
        .catalog()
        .is_some_and(|catalog| catalog.get(DEFINITION).is_some());
    if !has_definition {
        let (paths, errors, found_by) = locate(fs);
        return Ok(Located {
            files: paths.into_iter().map(|p| (p, found_by)).collect(),
            by_catalog: false,
            errors,
        });
    }
    let located = ctx.locate_artifact_files(&[DEFINITION])?;
    let mut errors = located.errors;
    errors.extend(located.unresolved.into_iter().map(|u| {
        ForensicError::other(
            "catalog",
            format!(
                "{DEFINITION}: source {:?} was not searched: {}",
                u.source, u.reason
            ),
        )
    }));
    for note in &located.notes {
        debug!("windows.prefetch: {DEFINITION}: {note}");
    }
    Ok(Located {
        files: located
            .files
            .into_iter()
            .map(|f| (f.path, f.found_by))
            .collect(),
        by_catalog: true,
        errors,
    })
}

/// The prefetch files on `fs`, sorted, the errors met while listing them, and whether they were in
/// the prefetch folder or found by name. This crate's own search, for a run with no artifact
/// catalog.
fn locate(fs: &dyn FileSystem) -> (Vec<FPathBuf>, Vec<ForensicError>, FoundBy) {
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
            return (paths, errors, FoundBy::Location);
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
    (paths, errors, FoundBy::FileName)
}

fn is_pf(path: &FPath) -> bool {
    path.file_name()
        .is_some_and(|n| n.to_ascii_lowercase().ends_with(".pf"))
}

impl ArtifactParserFactory for PrefetchParserFactory {
    fn descriptor(&self) -> &ParserDescriptor {
        &self.descriptor
    }

    /// A filesystem to search. Deliberately does not search it here: [`Self::open`] would only
    /// have to walk it again.
    fn can_parse(&self, ctx: &ParseContext<'_>) -> bool {
        ctx.vfs().is_some()
    }

    fn open(&self, ctx: &ParseContext<'_>) -> ForensicResult<ParserRun> {
        let fs = ctx.vfs().ok_or_else(|| {
            ForensicError::missing_data(
                "FileSystem source required",
                CompactString::const_new("PrefetchParserFactory"),
            )
        })?;
        let located = locate_for(ctx, fs.as_ref())?;
        let definition = located.by_catalog.then_some(DEFINITION);
        let host = ctx.host().to_string();
        let acquisition = ctx.acquisition();
        let mut out: Vec<ForensicResult<ForensicData>> =
            located.errors.into_iter().map(Err).collect();
        for (path, found_by) in located.files {
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
                        .map(|mut data| {
                            data.set(dictionary::ARTIFACT_LOCATED_BY, found_by.as_str());
                            if let Some(definition) = definition {
                                data.set(dictionary::ARTIFACT_DEFINITION, definition);
                            }
                            Ok(data)
                        }),
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

    use super::{PrefetchParserFactory, DEFINITION};

    /// `WindowsPrefetchFiles` as ForensicArtifacts defines it, restated here: this crate can't
    /// depend on `frnsc-artifacts`, and a pinned copy fails loudly if the definition changes.
    fn catalog() -> Arc<dyn ArtifactCatalog> {
        use std::borrow::Cow;
        let def = ArtifactDefinition {
            name: Cow::Borrowed(DEFINITION),
            aliases: Cow::Borrowed(&[]),
            doc: Cow::Borrowed(""),
            sources: Cow::Owned(vec![SourceEntry {
                source: ArtifactSource::File {
                    paths: Cow::Borrowed(&[Cow::Borrowed(r"%%environ_systemroot%%\Prefetch\*.pf")]),
                    separator: Separator::Backslash,
                },
                supported_os: Cow::Borrowed(&[]),
            }]),
            supported_os: Cow::Borrowed(&[Os::Windows]),
            urls: Cow::Borrowed(&[]),
        };
        Arc::new(SliceCatalog::new(vec![def]).unwrap())
    }

    fn run(fs: Arc<dyn FileSystem>) -> Vec<ForensicResult<ForensicData>> {
        run_with(TriageSources::builder().vfs(fs).build())
    }

    fn run_with_catalog(fs: Arc<dyn FileSystem>) -> Vec<ForensicResult<ForensicData>> {
        run_with(TriageSources::builder().vfs(fs).catalog(catalog()).build())
    }

    fn run_with(sources: TriageSources) -> Vec<ForensicResult<ForensicData>> {
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
            assert_eq!(
                r.field_as_str(dictionary::ARTIFACT_LOCATED_BY),
                Some("location")
            );
            // No catalog, so no definition matched: none is claimed.
            assert!(r.field(dictionary::ARTIFACT_DEFINITION).is_none());
        }
    }

    fn collection() -> Arc<dyn FileSystem> {
        Arc::new(InMemoryVirtualFileSystem::new().with_file(
            "host/CopiedFiles/prefetch/CMD.EXE-087B4001.pf",
            fixture("17/C/Windows/Prefetch/CMD.EXE-087B4001.pf"),
        ))
    }

    #[test]
    fn declares_its_catalog_definition() {
        let parser = PrefetchParserFactory::new();
        let declared: Vec<&str> = parser
            .descriptor()
            .requirements
            .iter()
            .filter_map(|r| match r {
                Requirement::Artifact(a) => Some(&*a.name),
                _ => None,
            })
            .collect();
        assert_eq!(declared, vec![DEFINITION]);
    }

    #[test]
    fn with_a_catalog_the_prefetch_folder_is_found_at_the_definitions_location() {
        let fs: Arc<dyn FileSystem> = Arc::new(ChRootFileSystem::new(
            "./artifacts/30/C",
            Arc::new(StdVirtualFS::new()),
        ));
        let records = run_with_catalog(fs);
        assert!(records.iter().all(|r| r.is_ok()), "{records:?}");
        assert!(!records.is_empty());
        for r in records.iter().map(|r| r.as_ref().unwrap()) {
            assert_eq!(
                r.field_as_str(dictionary::ARTIFACT_DEFINITION),
                Some(DEFINITION)
            );
            assert_eq!(
                r.field_as_str(dictionary::ARTIFACT_LOCATED_BY),
                Some("location")
            );
        }
    }

    #[test]
    fn with_a_catalog_a_collection_is_searched_by_the_definitions_file_names() {
        let records = run_with_catalog(collection());
        assert!(records.iter().all(|r| r.is_ok()), "{records:?}");
        assert!(!records.is_empty());
        for r in records.iter().map(|r| r.as_ref().unwrap()) {
            assert_eq!(
                r.field_as_str(dictionary::ARTIFACT_DEFINITION),
                Some(DEFINITION)
            );
            assert_eq!(
                r.field_as_str(dictionary::ARTIFACT_LOCATED_BY),
                Some("file_name")
            );
        }
    }

    #[test]
    fn without_a_catalog_a_collection_is_still_found_by_name() {
        let records = run(collection());
        let first = records[0].as_ref().unwrap();
        assert_eq!(
            first.field_as_str(dictionary::ARTIFACT_LOCATED_BY),
            Some("file_name")
        );
        assert!(first.field(dictionary::ARTIFACT_DEFINITION).is_none());
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
