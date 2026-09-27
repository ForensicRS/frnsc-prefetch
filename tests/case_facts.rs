//! Prefetch files from real (CTF) machines, checked against the `prefetch-run` facts of the
//! forensic-testenv cases, which were read with an independent parser. Skipped when the case is
//! not fetched (`forensic-testenv/tools/fetch.py --case unizar-bolas-cocido`).

use forensic_rs::prelude::*;
use forensic_testdata::case_or_skip;
use frnsc_prefetch::prelude::*;

#[test]
fn unizar_bolas_cocido_prefetch_facts() {
    let case = case_or_skip!("unizar-bolas-cocido");
    let fs = StdVirtualFS::new();
    let mut checked = 0;
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
        let last = pf.last_run_times.first().map(|t| t.filetime() as i64);
        assert_eq!(last, want["last_run"].as_integer(), "{ctx}");
        checked += 1;
    }
    assert!(checked > 0, "the case has no prefetch-run facts");
}
