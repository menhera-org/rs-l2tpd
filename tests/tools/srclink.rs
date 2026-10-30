//! The source-link check (docs/testing.md, "Gates"): every function of
//! `src/kernel/linux/` carries a `// kernel:` comment naming a K fact, and
//! every K fact has the citation its explicit evidence-map scope requires.
//! Delegated/source-only facts need test citations; linux facts need production
//! citations. Lenient (reports) unless `SRCLINK_STRICT=1`.

mod citations;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

fn function(line: &str) -> bool {
    line.split_once("fn ").is_some_and(|(prefix, _)| {
        prefix.split_whitespace().all(|word| {
            matches!(
                word,
                "pub"
                    | "pub(crate)"
                    | "pub(super)"
                    | "pub(self)"
                    | "const"
                    | "async"
                    | "unsafe"
                    | "extern"
                    | "\"C\""
            )
        })
    })
}

fn k_facts(kernel_md: &Path) -> BTreeSet<String> {
    fs::read_to_string(kernel_md)
        .expect("docs/spec/kernel.md")
        .lines()
        .filter_map(|line| {
            let row = line.strip_prefix("| K")?;
            let (digits, rest) = row.split_once(" | ")?;
            if !digits.chars().all(|c| c.is_ascii_digit()) || rest.starts_with("Removed") {
                return None;
            }
            Some(format!("K{digits}"))
        })
        .collect()
}

/// (functions without a citation, facts cited)
fn scan(dir: &Path) -> (Vec<String>, BTreeSet<String>) {
    let mut uncited = Vec::new();
    let mut facts = BTreeSet::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return (uncited, facts);
    };
    for entry in entries {
        let path = entry.unwrap().path();
        if path.is_dir() {
            let (u, f) = scan(&path);
            uncited.extend(u);
            facts.extend(f);
            continue;
        }
        let text = fs::read_to_string(&path).unwrap();
        let mut pending: Option<String> = None; // a `kernel:` comment waiting for its fn
        for line in text.lines() {
            let trimmed = line.trim_start();
            if let Some(cite) = trimmed.strip_prefix("// kernel:") {
                for token in cite.split(|c: char| !c.is_ascii_alphanumeric()) {
                    if token.len() > 1
                        && token.starts_with('K')
                        && token[1..].chars().all(|c| c.is_ascii_digit())
                    {
                        facts.insert(token.to_string());
                    }
                }
                pending = Some(cite.to_string());
            } else if function(trimmed) {
                if pending.take().is_none() {
                    uncited.push(format!(
                        "{}: {}",
                        path.display(),
                        trimmed.split('(').next().unwrap_or(trimmed)
                    ));
                }
            } else if !trimmed.starts_with("//") && !trimmed.starts_with('#') && !trimmed.is_empty()
            {
                pending = None;
            }
        }
    }
    (uncited, facts)
}

#[test]
fn scoped_and_qualified_functions_are_checked() {
    for line in [
        "fn f() {}",
        "pub(super) fn f() {}",
        "pub(crate) const fn f() {}",
        "const fn f() {}",
        "async fn f() {}",
    ] {
        assert!(function(line), "{line}");
    }
    assert!(!function("// fn f() is only a comment"));
}

#[test]
fn kernel_code_cites_the_facts() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let facts = k_facts(&root.join("docs/spec/kernel.md"));
    let (uncited, cited) = scan(&root.join("src/kernel/linux"));
    let classifications =
        scopes(&fs::read_to_string(root.join("docs/kernel-evidence.md")).unwrap());
    let mut tests = BTreeMap::new();
    citations::cited(&root.join("src"), &mut tests);
    citations::cited(&root.join("tests"), &mut tests);
    for (id, scope) in &classifications {
        assert!(
            facts.contains(id) || scope == "removed",
            "unknown active evidence fact: {id}"
        );
    }
    let missing: Vec<_> = facts
        .iter()
        .filter(|fact| {
            let scope = classifications
                .get(*fact)
                .unwrap_or_else(|| panic!("no scope for {fact}"));
            !covered(fact, scope, &cited, &tests)
        })
        .collect();
    for fact in facts
        .iter()
        .filter(|fact| classifications[*fact] != "linux")
    {
        println!(
            "classified evidence: {fact} ({}): {:?}",
            classifications[fact],
            tests.get(fact)
        );
    }
    println!(
        "source links: {} facts, {} cited, {} functions without a citation",
        facts.len(),
        cited.len(),
        uncited.len()
    );
    for f in &uncited {
        println!("uncited: {f}");
    }
    for f in &missing {
        println!("fact missing required citation: {f}");
    }
    assert!(!facts.is_empty(), "no K facts found");
    if std::env::var_os("SRCLINK_STRICT").is_some() {
        assert!(uncited.is_empty() && missing.is_empty());
    }
}

// Scope is explicit: an evidence row substitutes for a production citation
// only when the maintainer classified the fact as delegated or source-only.
fn scopes(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in text.lines().filter(|line| line.starts_with("| K")) {
        let columns: Vec<_> = line.split('|').map(str::trim).collect();
        assert_eq!(columns.len(), 5, "malformed evidence row: {line}");
        let (id, evidence, scope) = (columns[1], columns[2], columns[3]);
        assert!(citations::is_rule_id(id) && id.starts_with('K'), "{id}");
        assert!(!evidence.is_empty(), "missing evidence: {id}");
        assert!(
            matches!(scope, "linux" | "delegated" | "source-only" | "removed"),
            "unknown source-link scope for {id}: {scope}"
        );
        assert!(
            out.insert(id.to_owned(), scope.to_owned()).is_none(),
            "duplicate {id}"
        );
    }
    out
}

fn covered(
    fact: &str,
    scope: &str,
    production: &BTreeSet<String>,
    tests: &BTreeMap<String, Vec<String>>,
) -> bool {
    match scope {
        "linux" => production.contains(fact),
        "delegated" | "source-only" => tests
            .get(fact)
            .is_some_and(|locations| !locations.is_empty()),
        _ => false,
    }
}

#[test]
fn classified_facts_need_the_evidence_and_the_right_citation() {
    let map = scopes(
        "| K13 | upstream socket | delegated |\n| K33 | IPv6 down | source-only |\n| K1 | netlink | linux |",
    );
    let production = BTreeSet::from(["K1".into(), "K33".into()]);
    let tests = BTreeMap::from([("K13".into(), vec!["test.rs:1 (bind)".into()])]);
    assert!(covered("K1", &map["K1"], &production, &tests));
    assert!(covered("K13", &map["K13"], &production, &tests));
    assert!(!covered("K33", &map["K33"], &production, &tests));
    assert!(!covered("K13", "linux", &production, &tests));
    for invalid in [
        "| K1 | evidence | typo |",
        "| K1 | | delegated |",
        "| K1 | missing scope |",
        "| K1 | one | linux |\n| K1 | two | delegated |",
    ] {
        assert!(
            std::panic::catch_unwind(|| scopes(invalid)).is_err(),
            "{invalid}"
        );
    }
}
