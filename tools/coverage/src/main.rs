use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fs,
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
type Span = [u64; 4];
type Condition = (Span, Span, usize);
type Mapping = Vec<Span>;

fn require(ok: bool, message: &str) -> Result<()> {
    if ok { Ok(()) } else { Err(message.into()) }
}

fn array(value: &Value) -> Result<&Vec<Value>> {
    value.as_array().ok_or_else(|| "expected array".into())
}

fn number(value: &Value) -> Result<u64> {
    value
        .as_u64()
        .ok_or_else(|| "expected nonnegative integer".into())
}

fn string(value: &Value) -> Result<&str> {
    value.as_str().ok_or_else(|| "expected string".into())
}

fn flag(value: &Value) -> Result<bool> {
    value.as_bool().ok_or_else(|| "expected boolean".into())
}

fn keys(value: &Value, allowed: &[&str]) -> Result<()> {
    let object = value.as_object().ok_or("expected object")?;
    require(
        object.keys().all(|k| allowed.contains(&k.as_str())),
        "unsupported object field",
    )
}

fn row(value: &Value, len: usize) -> Result<&Vec<Value>> {
    let values = array(value)?;
    require(values.len() == len, "unsupported coverage tuple")?;
    Ok(values)
}

fn span(values: &[Value], lengths: &[usize]) -> Result<Span> {
    let mut result = [0; 4];
    for (out, value) in result.iter_mut().zip(values) {
        *out = number(value)?;
    }
    require(
        (result[0], result[1]) < (result[2], result[3]),
        "empty or reversed source span",
    )?;
    for [line, column] in [[result[0], result[1]], [result[2], result[3]]] {
        let length = line.checked_sub(1).and_then(|n| lengths.get(n as usize));
        require(
            length.is_some_and(|n| column > 0 && column <= *n as u64 + 1),
            "source coordinate outside file",
        )?;
    }
    Ok(result)
}

fn source_files(
    root: &Path,
    directory: &Path,
    result: &mut BTreeMap<String, String>,
) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        require(
            !entry.file_type()?.is_symlink(),
            "source symlink is unsupported",
        )?;
        if path.is_dir() {
            source_files(root, &path, result)?;
        } else if path.extension().is_some_and(|s| s == "rs") {
            let relative = path
                .strip_prefix(root)?
                .to_str()
                .ok_or("non-UTF8 source path")?;
            let output = Command::new("git")
                .args(["--no-pager", "hash-object", "--no-filters", "--", relative])
                .current_dir(root)
                .output()?;
            require(output.status.success(), "git hash-object failed")?;
            result.insert(
                relative.to_owned(),
                String::from_utf8(output.stdout)?.trim().to_owned(),
            );
        }
    }
    Ok(())
}

fn manifest(root: &Path) -> Result<Value> {
    let mut sources = BTreeMap::new();
    source_files(root, &root.join("src"), &mut sources)?;
    require(!sources.is_empty(), "empty source inventory")?;
    Ok(json!({"version": 2, "sources": sources}))
}

#[derive(Clone)]
struct Segment {
    line: u64,
    column: u64,
    count: u64,
    counted: bool,
    entry: bool,
    gap: bool,
}

// Mirrors LLVM LineCoverageStats: wrapped count and non-gap region entries.
fn lines(values: &Value, lengths: &[usize]) -> Result<BTreeMap<u64, bool>> {
    let mut segments = Vec::new();
    let mut previous = (0, 0);
    for value in array(values)? {
        let v = row(value, 6)?;
        let s = Segment {
            line: number(&v[0])?,
            column: number(&v[1])?,
            count: number(&v[2])?,
            counted: flag(&v[3])?,
            entry: flag(&v[4])?,
            gap: flag(&v[5])?,
        };
        require(
            previous < (s.line, s.column),
            "segments are not strictly ordered",
        )?;
        let length = s.line.checked_sub(1).and_then(|n| lengths.get(n as usize));
        require(
            length.is_some_and(|n| s.column > 0 && s.column <= *n as u64 + 1),
            "segment outside source",
        )?;
        require(s.counted || s.count == 0, "uncounted segment has a counter")?;
        previous = (s.line, s.column);
        segments.push(s);
    }
    let mut result = BTreeMap::new();
    let (Some(first), Some(last)) = (segments.first(), segments.last()) else {
        return Ok(result);
    };
    let mut next = 0;
    let mut wrapped: Option<&Segment> = None;
    for line in first.line..=last.line {
        let start = next;
        while next < segments.len() && segments[next].line == line {
            next += 1;
        }
        let current = &segments[start..next];
        let entries: Vec<_> = current
            .iter()
            .filter(|s| s.counted && s.entry && !s.gap)
            .collect();
        let skipped = current.first().is_some_and(|s| !s.counted && s.entry);
        let mapped = (!skipped && (wrapped.is_some_and(|s| s.counted) || !entries.is_empty()))
            || current.iter().any(|s| s.entry && s.counted);
        if mapped {
            let count = entries
                .iter()
                .fold(wrapped.map_or(0, |s| s.count), |n, s| n.max(s.count));
            result.insert(line, count > 0);
        }
        if let Some(s) = current.last() {
            wrapped = Some(s);
        }
    }
    Ok(result)
}

#[derive(Clone, Default, Debug)]
struct FileCoverage {
    lines: BTreeMap<u64, bool>,
    conditions: BTreeMap<Condition, [bool; 2]>,
    raw_lines: u64,
    raw_covered_lines: u64,
    raw_outcomes: u64,
    raw_covered_outcomes: u64,
}

fn summary(value: &Value, kind: &str) -> Result<(u64, u64)> {
    let count = number(&value[kind]["count"])?;
    let covered = number(&value[kind]["covered"])?;
    require(covered <= count, "covered count exceeds total")?;
    Ok((count, covered))
}

fn analyze(export: &Value, root: &Path) -> Result<BTreeMap<String, FileCoverage>> {
    keys(export, &["type", "version", "data", "cargo_llvm_cov"])?;
    require(
        string(&export["type"])? == "llvm.coverage.json.export"
            && string(&export["version"])? == "3.1.0",
        "unsupported LLVM export schema",
    )?;
    let data = array(&export["data"])?;
    require(data.len() == 1, "expected one combined LLVM mapping")?;
    let data = &data[0];
    keys(data, &["files", "functions", "totals"])?;
    let source_root = root.join("src");
    let mut files = BTreeMap::new();
    let mut lengths = BTreeMap::new();
    let mut file_branches: BTreeMap<String, BTreeMap<Vec<u64>, usize>> = BTreeMap::new();
    for file in array(&data["files"])? {
        keys(
            file,
            &[
                "filename",
                "segments",
                "branches",
                "expansions",
                "mcdc_records",
                "summary",
            ],
        )?;
        let filename = string(&file["filename"])?;
        let path = Path::new(filename);
        if !path.starts_with(&source_root) {
            continue;
        }
        require(path.canonicalize()? == path, "noncanonical source filename")?;
        require(
            array(&file["expansions"])?.is_empty() && array(&file["mcdc_records"])?.is_empty(),
            "expansions and MC/DC are unsupported",
        )?;
        let source = fs::read_to_string(path)?;
        let sizes: Vec<_> = source.split('\n').map(str::len).collect();
        let covered_lines = lines(&file["segments"], &sizes)?;
        let (raw_lines, raw_covered_lines) = summary(&file["summary"], "lines")?;
        require(
            covered_lines.len() as u64 <= raw_lines
                && (raw_lines == 0 || !covered_lines.is_empty()),
            "line mapping disagrees with LLVM denominator",
        )?;
        let (raw_outcomes, raw_covered_outcomes) = summary(&file["summary"], "branches")?;
        let coverage = FileCoverage {
            lines: covered_lines,
            raw_lines,
            raw_covered_lines,
            raw_outcomes,
            raw_covered_outcomes,
            ..FileCoverage::default()
        };
        require(
            files.insert(filename.to_owned(), coverage).is_none(),
            "duplicate file mapping",
        )?;
        let mut branches = BTreeMap::new();
        for value in array(&file["branches"])? {
            let v = row(value, 9)?;
            span(v, &sizes)?;
            let numbers = v.iter().map(number).collect::<Result<Vec<_>>>()?;
            require(
                numbers[6..] == [0, 0, 4],
                "unsupported branch file IDs or kind",
            )?;
            *branches.entry(numbers).or_default() += 1;
        }
        file_branches.insert(filename.to_owned(), branches);
        lengths.insert(filename.to_owned(), sizes);
    }
    require(!files.is_empty(), "no production coverage files")?;
    let mut mappings: BTreeMap<(String, Span), Mapping> = BTreeMap::new();

    let mut executed_region_lines: BTreeMap<String, BTreeSet<u64>> = BTreeMap::new();
    let mut seen_files = BTreeSet::new();
    let mut names = BTreeSet::new();
    for function in array(&data["functions"])? {
        keys(
            function,
            &[
                "name",
                "count",
                "filenames",
                "regions",
                "branches",
                "mcdc_records",
            ],
        )?;
        let filenames = array(&function["filenames"])?;
        let first = filenames.first().ok_or("function has no file")?;
        let filename = string(first)?;
        if !Path::new(filename).starts_with(&source_root) {
            continue;
        }
        require(filenames.len() == 1, "multi-file function is unsupported")?;
        let sizes = lengths
            .get(filename)
            .ok_or("function file has no file mapping")?;
        let name = string(&function["name"])?;
        require(names.insert(name), "duplicate function name")?;
        number(&function["count"])?;
        require(
            array(&function["mcdc_records"])?.is_empty(),
            "MC/DC function is unsupported",
        )?;
        let mut regions = Vec::new();
        for value in array(&function["regions"])? {
            let v = row(value, 8)?;
            span(v, sizes)?;
            let mut r = v.iter().map(number).collect::<Result<Vec<_>>>()?;
            require(r[5..] == [0, 0, 0], "unsupported region file IDs or kind")?;
            if r[4] > 0 {
                executed_region_lines
                    .entry(filename.to_owned())
                    .or_default()
                    .extend(r[0]..=r[2]);
            }
            r.remove(4);
            regions.push(r);
        }
        let first = regions.first().ok_or("function has no regions")?;
        let owner = [first[0], first[1], first[2], first[3]];
        let mut branch_spans = Vec::new();
        let mut ordinals = BTreeMap::new();
        for value in array(&function["branches"])? {
            let v = row(value, 9)?;
            let location = span(v, sizes)?;
            let numbers = v.iter().map(number).collect::<Result<Vec<_>>>()?;
            require(numbers[6..] == [0, 0, 4], "unsupported function branch")?;
            let remaining = file_branches
                .get_mut(filename)
                .and_then(|b| b.get_mut(&numbers))
                .ok_or("function branch absent from file mapping")?;
            require(
                *remaining > 0,
                "function branch multiplicity exceeds file mapping",
            )?;
            *remaining -= 1;
            let ordinal = ordinals.entry(location).or_insert(0);
            let coverage = files.get_mut(filename).ok_or("missing file")?;
            let outcomes = coverage
                .conditions
                .entry((owner, location, *ordinal))
                .or_insert([false; 2]);
            outcomes[0] |= numbers[4] > 0;
            outcomes[1] |= numbers[5] > 0;
            *ordinal += 1;
            branch_spans.push(location);
        }
        match mappings.get_mut(&(filename.to_owned(), owner)) {
            Some(previous_branches) => {
                // LLVM can omit all branches in an unused executable copy.
                if previous_branches.is_empty() {
                    *previous_branches = branch_spans;
                } else if !branch_spans.is_empty() {
                    require(
                        *previous_branches == branch_spans,
                        &format!("{filename} {owner:?}: ambiguous branch layout for {name}"),
                    )?;
                }
            }
            None => {
                mappings.insert((filename.to_owned(), owner), branch_spans);
            }
        }

        seen_files.insert(filename.to_owned());
    }
    for (filename, file) in &files {
        require(
            seen_files.contains(filename),
            "file has no function mappings",
        )?;
        for (line, covered) in &file.lines {
            require(
                !covered
                    || executed_region_lines
                        .get(filename)
                        .is_some_and(|lines| lines.contains(line)),
                "covered line has no executed function region",
            )?;
        }
        // JSON omits folding flags. Reconcile the executable denominator;
        // reject partial folding or ambiguous ownership instead of guessing.
        require(
            file.conditions.len() as u64 * 2 == file.raw_outcomes,
            &format!("{filename}: executable branch denominator disagrees with LLVM"),
        )?;
        for (branch, remaining) in &file_branches[filename] {
            require(
                *remaining == 0 || (branch[4] == 0 && branch[5] == 0),
                "unmatched file branch has executions",
            )?;
        }
    }
    Ok(files)
}

fn mapping_identity(
    export: &Value,
    root: &Path,
    coverage: &BTreeMap<String, FileCoverage>,
) -> Result<Value> {
    let data = &export["data"][0];
    let source_root = root.join("src");
    let mut files = BTreeMap::new();
    let mut functions = BTreeMap::new();
    for file in array(&data["files"])? {
        let name = string(&file["filename"])?;
        if Path::new(name).starts_with(&source_root) {
            let lines = coverage
                .get(name)
                .ok_or("file missing from line inventory")?
                .lines
                .keys()
                .copied()
                .collect::<Vec<_>>();
            files.insert(name.to_owned(), lines);
        }
    }
    for function in array(&data["functions"])? {
        let filenames = array(&function["filenames"])?;
        let filename = string(filenames.first().ok_or("missing filename")?)?;
        if !Path::new(filename).starts_with(&source_root) {
            continue;
        }
        let mut identity = function.clone();
        identity
            .as_object_mut()
            .ok_or("expected function object")?
            .remove("count");
        for field in ["regions", "branches"] {
            for value in identity[field].as_array_mut().ok_or("expected mappings")? {
                let row = value.as_array_mut().ok_or("expected mapping tuple")?;
                row[4] = json!(0);
                if field == "branches" {
                    row[5] = json!(0);
                }
            }
        }
        functions.insert(string(&function["name"])?.to_owned(), identity);
    }
    Ok(json!({"files":files, "functions":functions}))
}

fn run() -> Result<bool> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    require(
        args.len() == 4,
        "usage: phase6-coverage snapshot|check ROOT MANIFEST EXPORT",
    )?;
    let root = PathBuf::from(&args[1]).canonicalize()?;
    let manifest_path = PathBuf::from(&args[2]);
    require(
        args[0] == "snapshot" || args[0] == "check",
        "invalid command",
    )?;
    let export: Value = serde_json::from_slice(&fs::read(&args[3])?)?;
    let files = analyze(&export, &root)?;
    let mut current = manifest(&root)?;
    current["mapping"] = mapping_identity(&export, &root, &files)?;
    if args[0] == "snapshot" {
        fs::write(manifest_path, serde_json::to_vec_pretty(&current)?)?;
        return Ok(true);
    }
    let expected: Value = serde_json::from_slice(&fs::read(manifest_path)?)?;
    require(
        expected == current,
        "source inventory or mappings changed since snapshot",
    )?;

    let (mut total_lines, mut covered_lines, mut total_outcomes, mut covered_outcomes) =
        (0, 0, 0, 0);
    for (name, file) in files {
        let covered = file.lines.values().filter(|v| **v).count();
        let outcomes = file.conditions.values().flatten().filter(|v| **v).count();
        println!(
            "{name}: lines {covered}/{}; outcomes {outcomes}/{}; raw LLVM lines {}/{}; raw outcomes {}/{}",
            file.lines.len(),
            file.conditions.len() * 2,
            file.raw_covered_lines,
            file.raw_lines,
            file.raw_covered_outcomes,
            file.raw_outcomes
        );
        for (line, covered) in &file.lines {
            if !covered {
                println!("  missing line {line}");
            }
        }
        for ((owner, span, ordinal), outcomes) in &file.conditions {
            for (arm, covered) in outcomes.iter().enumerate() {
                if !covered {
                    println!(
                        "  missing condition {span:?} occurrence {ordinal} owner {owner:?} {}",
                        if arm == 0 { "true" } else { "false" }
                    );
                }
            }
        }
        total_lines += file.lines.len();
        covered_lines += covered;
        total_outcomes += file.conditions.len() * 2;
        covered_outcomes += outcomes;
    }
    require(
        total_lines > 0 && total_outcomes > 0,
        "empty coverage denominator",
    )?;
    let passed = covered_lines == total_lines && covered_outcomes == total_outcomes;
    println!("MERGED_SOURCE_LINES={covered_lines}/{total_lines}");
    println!("MERGED_SOURCE_OUTCOMES={covered_outcomes}/{total_outcomes}");
    println!(
        "MERGED_SOURCE_GATE={}",
        if passed { "PASS" } else { "FAIL" }
    );
    Ok(passed)
}

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(error) => {
            eprintln!("coverage error: {error}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "phase6-coverage-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(root.join("src")).unwrap();
            fs::write(
                root.join("src/example.rs"),
                "                    \n                    \n                    \n",
            )
            .unwrap();
            Self(root.canonicalize().unwrap())
        }
        fn export(&self, copies: &[[u64; 2]], repeated: bool) -> Value {
            let filename = self.0.join("src/example.rs").to_str().unwrap().to_owned();
            let mut functions = Vec::new();
            let mut branches = Vec::new();
            for (i, counts) in copies.iter().enumerate() {
                let branch = json!([2, 2, 2, 3, counts[0], counts[1], 0, 0, 4]);
                let mut local = vec![branch];
                if repeated {
                    local.push(json!([2, 2, 2, 3, 0, 1, 0, 0, 4]));
                }
                branches.extend(local.clone());
                functions.push(json!({
                    "name": format!("instance-{i}"), "count":1, "filenames":[filename],
                    "regions":[[1,1,1,20,1,0,0,0],[2,1,3,2,1,0,0,0]],
                    "branches":local, "mcdc_records":[]
                }));
            }
            let count = if repeated { 4 } else { 2 };
            json!({
                "type":"llvm.coverage.json.export", "version":"3.1.0",
                "data":[{"totals":{}, "functions":functions, "files":[{
                    "filename":filename, "branches":branches, "expansions":[], "mcdc_records":[],
                    "segments":[[1,1,1,true,true,false],[3,2,0,false,false,false]],
                    "summary":{"lines":{"count":3,"covered":3}, "branches":{"count":count,"covered":count}}
                }]}]
            })
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn complementary_copies_merge_both_outcomes_without_merging_distinct_conditions() {
        let fixture = Fixture::new();
        let report = analyze(&fixture.export(&[[1, 0], [0, 1]], false), &fixture.0).unwrap();
        let file = report.values().next().unwrap();
        assert_eq!(
            file.lines,
            BTreeMap::from([(1, true), (2, true), (3, true)])
        );
        assert_eq!(file.conditions.len(), 1);
        assert_eq!(*file.conditions.values().next().unwrap(), [true, true]);

        let report = analyze(&fixture.export(&[[1, 0], [0, 1]], true), &fixture.0).unwrap();
        let file = report.values().next().unwrap();
        assert_eq!(file.conditions.len(), 2);
        assert_eq!(
            file.conditions
                .values()
                .filter(|v| **v == [true, true])
                .count(),
            1
        );
        assert_eq!(
            file.conditions
                .values()
                .filter(|v| **v == [false, true])
                .count(),
            1
        );
    }

    #[test]
    fn a_missing_outcome_stays_missing() {
        let fixture = Fixture::new();
        let report = analyze(&fixture.export(&[[9, 0], [3, 0]], false), &fixture.0).unwrap();
        assert_eq!(
            *report
                .values()
                .next()
                .unwrap()
                .conditions
                .values()
                .next()
                .unwrap(),
            [true, false]
        );
    }

    #[test]
    fn different_spans_on_one_line_stay_separate() {
        let fixture = Fixture::new();
        let mut export = fixture.export(&[[1, 0]], true);
        export["data"][0]["functions"][0]["branches"][1][1] = json!(4);
        export["data"][0]["functions"][0]["branches"][1][3] = json!(5);
        export["data"][0]["files"][0]["branches"][1][1] = json!(4);
        export["data"][0]["files"][0]["branches"][1][3] = json!(5);
        let report = analyze(&export, &fixture.0).unwrap();
        assert_eq!(report.values().next().unwrap().conditions.len(), 2);
        assert!(
            report
                .values()
                .next()
                .unwrap()
                .conditions
                .values()
                .all(|v| *v != [true, true])
        );
    }

    #[test]
    fn folded_unused_copies_do_not_erase_executable_conditions() {
        let fixture = Fixture::new();
        let mut export = fixture.export(&[[0, 0], [1, 1]], false);
        export["data"][0]["functions"][0]["branches"] = json!([]);
        let report = analyze(&export, &fixture.0).unwrap();
        assert_eq!(
            *report
                .values()
                .next()
                .unwrap()
                .conditions
                .values()
                .next()
                .unwrap(),
            [true, true]
        );
    }

    #[test]
    fn unsupported_or_inconsistent_exports_fail() {
        let fixture = Fixture::new();
        let original = fixture.export(&[[1, 0], [0, 1]], false);
        for (pointer, value) in [
            ("/version", json!("4.0.0")),
            ("/data/0/files/0/segments/0/0", json!(99)),
            ("/data/0/files/0/segments/0/2", json!(-1)),
            ("/data/0/files/0/segments/0/3", json!(1)),
            ("/data/0/files/0/branches/0/8", json!(9)),
            ("/data/0/files/0/summary/branches/count", json!(1)),
            ("/data/0/files/0/summary/branches/covered", json!(3)),
            ("/data/0/files/0/expansions", json!([{}])),
            ("/data/0/functions/1/branches/0/1", json!(4)),
            ("/data/0/functions/1/filenames", json!(["missing"])),
            ("/data/0/functions/1/name", json!("instance-0")),
            ("/data/0/functions/1/regions/0/5", json!(1)),
            ("/data/0/functions/1/mcdc_records", json!([{}])),
            ("/data/0/files/0/filename", json!("outside")),
            ("/data/0/functions", json!([])),
        ] {
            let mut export = original.clone();
            *export.pointer_mut(pointer).unwrap() = value;
            assert!(
                analyze(&export, &fixture.0).is_err(),
                "accepted mutation {pointer}"
            );
        }
        for (pointer, value) in [
            ("/data", json!([])),
            ("/data/0/files/0/branches/0", json!([2, 2, 2, 3])),
            ("/data/0/files/0/segments/0", json!([1, 1])),
            ("/data/0/files/0/segments", json!([])),
            ("/data/0/functions/0/regions", json!([])),
        ] {
            let mut export = original.clone();
            *export.pointer_mut(pointer).unwrap() = value;
            assert!(
                analyze(&export, &fixture.0).is_err(),
                "accepted malformed tuple {pointer}"
            );
        }
        let mut export = original;
        export["unexpected"] = json!(true);
        assert!(analyze(&export, &fixture.0).is_err());
    }

    #[test]
    fn fabricated_covered_lines_without_any_executed_region_fail() {
        let fixture = Fixture::new();
        let mut export = fixture.export(&[[0, 0]], false);
        for region in export["data"][0]["functions"][0]["regions"]
            .as_array_mut()
            .unwrap()
        {
            region[4] = json!(0);
        }
        assert!(analyze(&export, &fixture.0).is_err());
    }

    #[test]
    fn line_stats_handle_wrapped_counts_skips_gaps_and_multiple_entries() {
        let sizes = vec![100; 7];
        let values = json!([
            [1, 1, 3, true, true, false],
            [3, 1, 0, false, true, false],
            [4, 1, 0, true, true, false],
            [4, 5, 99, true, true, true],
            [5, 1, 0, false, false, false],
            [6, 1, 0, true, true, false],
            [6, 4, 1, true, true, false],
            [7, 1, 0, false, true, false]
        ]);
        assert_eq!(
            lines(&values, &sizes).unwrap(),
            BTreeMap::from([(1, true), (2, true), (4, false), (5, true), (6, true)])
        );
        for values in [
            json!([[1, 1, 0, true, true, false], [1, 1, 1, true, true, false]]),
            json!([[1, 1, 1, false, false, false]]),
            json!([[0, 1, 1, true, true, false]]),
            json!([[1, 1010, 1, true, true, false]]),
        ] {
            assert!(lines(&values, &sizes).is_err());
        }
    }

    #[test]
    fn source_fingerprints_ignore_git_clean_filters() {
        let fixture = Fixture::new();
        for args in [
            vec!["--no-pager", "init", "--quiet"],
            vec![
                "--no-pager",
                "config",
                "filter.collapse.clean",
                "cat /dev/null",
            ],
        ] {
            let output = Command::new("git")
                .args(args)
                .current_dir(&fixture.0)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        fs::write(fixture.0.join(".gitattributes"), "*.rs filter=collapse\n").unwrap();
        let before = manifest(&fixture.0).unwrap();
        fs::write(fixture.0.join("src/example.rs"), "changed\n").unwrap();
        assert_ne!(before, manifest(&fixture.0).unwrap());
    }

    #[test]
    fn source_manifest_changes_with_contents_and_inventory() {
        let fixture = Fixture::new();
        let before = manifest(&fixture.0).unwrap();
        assert_eq!(before, manifest(&fixture.0).unwrap());
        fs::write(fixture.0.join("src/example.rs"), "changed\n").unwrap();
        assert_ne!(before, manifest(&fixture.0).unwrap());
        let modified = manifest(&fixture.0).unwrap();
        fs::write(fixture.0.join("src/new.rs"), "new\n").unwrap();
        assert_ne!(modified, manifest(&fixture.0).unwrap());
    }
}

#[cfg(test)]
mod mapping_tests {
    use super::*;

    #[test]
    fn inventory_rejects_missing_files_functions_and_changed_spans_but_accepts_new_counts() {
        let root = Path::new("/project");
        let source = json!({"data":[{"files":[{"filename":"/project/src/a.rs"},{"filename":"/project/src/b.rs"}],
            "functions":[{"name":"a", "count":1,"filenames":["/project/src/a.rs"],
                "regions":[[1,1,1,5,1,0,0,0]],"branches":[[1,2,1,3,1,0,0,0,4]]}]}]});
        let coverage: BTreeMap<String, FileCoverage> = ["a.rs", "b.rs"]
            .into_iter()
            .map(|name| {
                (
                    format!("/project/src/{name}"),
                    FileCoverage {
                        lines: BTreeMap::from([(1, true)]),
                        ..FileCoverage::default()
                    },
                )
            })
            .collect();
        let original = mapping_identity(&source, root, &coverage).unwrap();
        let mut missing_lines = coverage.clone();
        missing_lines
            .get_mut("/project/src/a.rs")
            .unwrap()
            .lines
            .clear();
        assert_ne!(
            original,
            mapping_identity(&source, root, &missing_lines).unwrap()
        );
        let mut counts = source.clone();
        counts["data"][0]["functions"][0]["count"] = json!(99);
        counts["data"][0]["functions"][0]["regions"][0][4] = json!(99);
        counts["data"][0]["functions"][0]["branches"][0][4] = json!(0);
        counts["data"][0]["functions"][0]["branches"][0][5] = json!(99);
        assert_eq!(
            original,
            mapping_identity(&counts, root, &coverage).unwrap()
        );
        for (pointer, value) in [
            ("/data/0/files", json!([{"filename":"/project/src/a.rs"}])),
            ("/data/0/functions", json!([])),
            ("/data/0/functions/0/regions/0/3", json!(6)),
            ("/data/0/functions/0/branches/0/3", json!(4)),
        ] {
            let mut changed = source.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert_ne!(
                original,
                mapping_identity(&changed, root, &coverage).unwrap(),
                "{pointer}"
            );
        }
    }
}
