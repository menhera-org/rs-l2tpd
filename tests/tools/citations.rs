//! Shared lexical test-citation reader for the traceability gates.
use std::collections::{BTreeMap, BTreeSet};
use std::{fs, path::Path};

pub(super) fn is_rule_id(s: &str) -> bool {
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

pub(super) fn cited(dir: &Path, out: &mut BTreeMap<String, Vec<String>>) {
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
