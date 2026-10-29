//! The source-link check (docs/testing.md, "Gates"): every function of
//! `src/kernel/linux/` carries a `// kernel:` comment naming a K fact, and
//! every K fact of `docs/spec/kernel.md` is cited at least once. Lenient
//! (reports) unless `SRCLINK_STRICT=1`.

use std::collections::BTreeSet;
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
    let missing: Vec<&String> = facts.iter().filter(|f| !cited.contains(*f)).collect();
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
        println!("fact never cited: {f}");
    }
    assert!(!facts.is_empty(), "no K facts found");
    if std::env::var_os("SRCLINK_STRICT").is_some() {
        assert!(uncited.is_empty() && missing.is_empty());
    }
}
