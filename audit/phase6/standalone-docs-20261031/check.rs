use std::fs;
use std::path::{Component, Path, PathBuf};

#[derive(Default)]
struct Counts {
    files: usize,
    links: usize,
    outside: usize,
}

fn normalize(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                result.pop();
            }
            Component::CurDir => {}
            component => result.push(component.as_os_str()),
        }
    }
    result
}

fn check(root: &Path, docs: &Path, path: &Path, counts: &mut Counts) {
    if path.is_dir() {
        let mut paths = fs::read_dir(path)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        paths.sort();
        for path in paths {
            check(root, docs, &path, counts);
        }
        return;
    }
    if path.extension().and_then(|extension| extension.to_str()) != Some("md") {
        return;
    }
    counts.files += 1;
    let source = fs::read_to_string(path).unwrap();
    let mut at = 0;
    while let Some(start) = source[at..].find("](") {
        let start = at + start + 2;
        let end = source[start..].find(')').unwrap() + start;
        let target = source[start..end]
            .split('#')
            .next()
            .unwrap()
            .trim_matches(['<', '>']);
        at = end + 1;
        if target.is_empty()
            || target.starts_with("https://")
            || target.starts_with("http://")
            || target.starts_with("mailto:")
        {
            continue;
        }
        counts.links += 1;
        let target = normalize(&path.parent().unwrap().join(target));
        if !target.starts_with(docs) {
            counts.outside += 1;
            println!(
                "{}: outside docs: {}",
                path.strip_prefix(root).unwrap().display(),
                target.strip_prefix(root).unwrap_or(&target).display()
            );
        } else {
            let resolved = target
                .canonicalize()
                .unwrap_or_else(|error| panic!("{}: {error}", target.display()));
            assert!(
                resolved.starts_with(docs),
                "link escapes docs through a symlink"
            );
        }
    }
}

fn main() {
    let root = PathBuf::from(std::env::args_os().nth(1).unwrap_or_else(|| ".".into()))
        .canonicalize()
        .unwrap();
    let docs = root.join("docs").canonicalize().unwrap();
    let mut counts = Counts::default();
    check(&root, &docs, &docs, &mut counts);
    println!(
        "files={} local_file_links={} outside={}",
        counts.files, counts.links, counts.outside
    );
    assert_eq!(counts.outside, 0, "docs must stand alone");
}
