//! Traceability from numbered spec rules to test declarations with `/// spec:`
//! doc comments. This lexical check does not prove execution or case coverage.
//! Lenient (reports missing citations) unless `RULEMAP_STRICT` is set.

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

/// Test declarations and their preceding rule doc comments. This deliberately
/// records source locations rather than claiming these tests ran: cfg/feature
/// selection and ignored/live-kernel suites must be checked by their runners.
fn test_citations(text: &str) -> Vec<(usize, String, BTreeSet<String>)> {
    let mut found = Vec::new();
    let mut pending = BTreeSet::new();
    let mut is_test = false;
    for (line_number, line) in text.lines().enumerate() {
        let line = line.trim();
        if let Some(doc) = line.strip_prefix("///") {
            if let Some((_, after)) = doc.split_once("spec:") {
                pending.extend(
                    after
                        .split(|c: char| !c.is_ascii_alphanumeric())
                        .filter(|token| is_rule_id(token))
                        .map(str::to_owned),
                );
            }
        } else if line.starts_with("#[") {
            is_test |= line == "#[test]" || line.starts_with("#[tokio::test");
        } else if let Some(declaration) = line
            .strip_prefix("fn ")
            .or_else(|| line.strip_prefix("async fn "))
        {
            if is_test && let Some((name, _)) = declaration.split_once('(') {
                found.push((line_number + 1, name.to_owned(), pending.clone()));
            }
            pending.clear();
            is_test = false;
        } else if !line.is_empty() {
            pending.clear();
            is_test = false;
        }
    }
    found
}

fn cited(dir: &Path, out: &mut BTreeMap<String, Vec<String>>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries {
        let path = entry.unwrap().path();
        if path.is_dir() {
            cited(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            for (line, name, rules) in test_citations(&fs::read_to_string(&path).unwrap()) {
                for rule in rules {
                    out.entry(rule)
                        .or_default()
                        .push(format!("{}:{line} ({name})", path.display(),));
                }
            }
        }
    }
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

#[test]
fn only_doc_comments_attached_to_tests_are_citations() {
    let source = concat!(
        "// spec: T1\nfn production() {}\n",
        "/// spec: T2\nfn helper() {}\n",
        "/// spec: T3, K5\n#[test]\nfn works() {}\n",
        "/// spec: T4\n#[test]\n#[ignore = \"live kernel\"]\nfn live() {}\n",
        "/// spec: T5\n#[tokio::test]\nasync fn async_case() {}\n",
        "/// spec: T6\nstruct Unrelated;\n#[test]\nfn no_claim() {}\n",
    );
    let found = test_citations(source);
    let rules: BTreeSet<_> = found
        .iter()
        .flat_map(|(_, _, ids)| ids.iter())
        .cloned()
        .collect();
    assert_eq!(
        rules,
        BTreeSet::from(["T3", "K5", "T4", "T5"].map(str::to_owned))
    );
    assert_eq!(
        found
            .iter()
            .map(|(_, name, _)| name.as_str())
            .collect::<Vec<_>>(),
        ["works", "live", "async_case", "no_claim"]
    );
}
