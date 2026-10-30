//! Traceability from numbered spec rules to test declarations with `/// spec:`
//! doc comments. This lexical check does not prove execution or case coverage.
//! Lenient (reports missing citations) unless `RULEMAP_STRICT` is set.

mod citations;
use citations::{cited, is_rule_id};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// A rule is defined by a line `X1. ...` or a table row `| X1 | ...`, X
/// being one of the page letters. A rule whose text begins with "Removed"
/// is exempt.
fn rules(spec_dir: &Path) -> BTreeMap<String, bool> {
    let mut out = BTreeMap::new();
    for entry in fs::read_dir(spec_dir).expect("docs/spec") {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "md") {
            continue;
        }
        for line in fs::read_to_string(&path).unwrap().lines() {
            let (id, rest) = match definition(line) {
                Some(found) => found,
                None => continue,
            };
            let removed = rest.trim_start().starts_with("Removed");
            out.insert(id, removed);
        }
    }
    out
}

/// `Some((id, text after the id))` for a definition line.
fn definition(line: &str) -> Option<(String, &str)> {
    let (candidate, rest) = if let Some(row) = line.strip_prefix("| ") {
        let (id, rest) = row.split_once(" | ")?;
        (id, rest)
    } else {
        let (id, rest) = line.split_once(". ")?;
        (id, rest)
    };
    is_rule_id(candidate).then(|| (candidate.to_string(), rest))
}

#[test]
fn every_rule_has_a_test_citation() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let rules = rules(&root.join("docs/spec"));
    let mut tests = BTreeMap::new();
    cited(&root.join("src"), &mut tests);
    cited(&root.join("tests"), &mut tests);
    let untested: Vec<&String> = rules
        .iter()
        .filter(|(id, removed)| !**removed && !tests.contains_key(*id))
        .map(|(id, _)| id)
        .collect();
    let active = rules.values().filter(|removed| !**removed).count();
    println!(
        "rule map: {} rules ({} active), {} linked to test declarations, {} without citations",
        rules.len(),
        active,
        active - untested.len(),
        untested.len()
    );
    for id in &untested {
        println!("without test citation: {id}");
    }
    for (id, locations) in &tests {
        assert!(rules.contains_key(id), "test cites undefined rule {id}");
        for location in locations {
            println!("{id}: {location}");
        }
    }
    assert!(!rules.is_empty(), "no rules found under docs/spec");
    if std::env::var_os("RULEMAP_STRICT").is_some() {
        assert!(
            untested.is_empty(),
            "{} rules without a test citation",
            untested.len()
        );
    }
}

#[test]
fn definitions_are_recognised() {
    assert_eq!(definition("T21. A **reconnect** is").unwrap().0, "T21");
    assert_eq!(
        definition("| R7 | Removed. x | — |").unwrap(),
        ("R7".into(), "Removed. x | — |")
    );
    assert!(definition("The daemon MUST").is_none());
    assert!(definition("| Field | Rule |").is_none());
    assert!(!is_rule_id("RFC"));
}
