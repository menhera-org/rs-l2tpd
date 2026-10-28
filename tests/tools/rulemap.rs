//! The rule map (docs/testing.md, "Gates"): every numbered rule of
//! `docs/spec/*.md` must be named by a `spec:` comment in `src/` or
//! `tests/`. Lenient (reports) unless `RULEMAP_STRICT=1`.

use std::collections::{BTreeMap, BTreeSet};
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

fn is_rule_id(s: &str) -> bool {
    let mut chars = s.chars();
    let letter = chars.next().filter(|c| "ACDEGHKLMOPRSTV".contains(*c));
    let digits: String = chars.collect();
    letter.is_some() && !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit())
}

/// Every id named after `spec:` in a line of a Rust file under `dir`.
fn cited(dir: &Path, out: &mut BTreeSet<String>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries {
        let path = entry.unwrap().path();
        if path.is_dir() {
            cited(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            for line in fs::read_to_string(&path).unwrap().lines() {
                let Some((_, after)) = line.split_once("spec:") else {
                    continue;
                };
                for token in after.split(|c: char| !c.is_ascii_alphanumeric()) {
                    if is_rule_id(token) {
                        out.insert(token.to_string());
                    }
                }
            }
        }
    }
}

#[test]
fn every_rule_has_a_test() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let rules = rules(&root.join("docs/spec"));
    let mut tests = BTreeSet::new();
    cited(&root.join("src"), &mut tests);
    cited(&root.join("tests"), &mut tests);
    let untested: Vec<&String> = rules
        .iter()
        .filter(|(id, removed)| !**removed && !tests.contains(*id))
        .map(|(id, _)| id)
        .collect();
    let active = rules.values().filter(|removed| !**removed).count();
    println!(
        "rule map: {} rules ({} active), {} cited by a test, {} untested",
        rules.len(),
        active,
        active - untested.len(),
        untested.len()
    );
    for id in &untested {
        println!("untested: {id}");
    }
    assert!(!rules.is_empty(), "no rules found under docs/spec");
    if std::env::var_os("RULEMAP_STRICT").is_some() {
        assert!(
            untested.is_empty(),
            "{} rules without a test",
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
