//! Prefetch files from real (CTF) machines, checked against the `prefetch-run` facts of the
//! forensic-testenv cases, which were read with an independent parser. Skipped when the case is
//! not fetched (`forensic-testenv/tools/fetch.py --case unizar-bolas-cocido`).

use std::sync::Arc;

use forensic_rs::prelude::*;
use forensic_rs::utils::testing::{assert_records_conform, collect_run, InMemoryVirtualFileSystem};
use forensic_testdata::case_or_skip;
use frnsc_prefetch::prelude::*;

#[test]
fn unizar_bolas_cocido_prefetch_facts() {
    let case = case_or_skip!("unizar-bolas-cocido");
    let fs = StdVirtualFS::new();
    let mut checked = 0;
    let mut collection = InMemoryVirtualFileSystem::new();
    for fact in case.facts("prefetch-run") {
        let path = case.fact_path(fact);
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let file = fs.open(FPath::new(path.to_str().unwrap())).unwrap();
        let pf = read_prefetch_file(&name, file)
            .unwrap_or_else(|e| panic!("{} {name}: {e:?}", fact.machine));
        let want = &fact.expect;
        let ctx = format!("{} {name} (verified by {})", fact.machine, fact.verified_by);
        assert_eq!(
            i64::from(pf.version),
            want["version"].as_integer().unwrap(),
            "{ctx}"
        );
        assert_eq!(pf.name, want["executable"].as_str().unwrap(), "{ctx}");
        assert_eq!(
            i64::from(pf.run_count),
            want["run_count"].as_integer().unwrap(),
            "{ctx}"
        );
        let last = pf
            .last_run_times
            .first()
            .map(|t| t.to_win_filetime().expect("after 1601") as i64);
        assert_eq!(last, want["last_run"].as_integer(), "{ctx}");
        collection.add_file(
            format!("{}/{name}", fact.machine),
            std::fs::read(&path).unwrap(),
        );
        checked += 1;
    }
    assert!(checked > 0, "the case has no prefetch-run facts");
    factory_records_conform(Arc::new(collection));
}

/// The pipeline records of the case's prefetch files carry only the declared fields.
fn factory_records_conform(fs: Arc<dyn FileSystem>) {
    let sources = TriageSources::builder().vfs(fs).build();
    let triage = TriageContext::new("HOST", "t");
    let cancellation = CancellationToken::new();
    let ctx = ParseContext::new(&sources, &triage, &cancellation);
    let parser = PrefetchParserFactory::new();
    let items = collect_run(parser.open(&ctx).unwrap()).unwrap();
    let records: Vec<&ForensicData> = items.iter().filter_map(|r| r.as_ref().ok()).collect();
    assert_records_conform(parser.descriptor(), records);
}
