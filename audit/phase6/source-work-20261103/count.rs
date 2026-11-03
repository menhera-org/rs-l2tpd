// Compare ordinary production-region executions in two snapshots of one binary.
use serde_json::{Value, json};
use std::{collections::BTreeMap, error::Error, fs};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn counts(export: &Value, root: &str) -> Result<BTreeMap<String, u64>> {
    if export["type"] != "llvm.coverage.json.export" || export["version"] != "3.1.0" {
        return Err("unsupported LLVM export".into());
    }
    let data = export["data"].as_array().ok_or("missing coverage data")?;
    if data.len() != 1 {
        return Err("expected one binary mapping".into());
    }
    let functions = data[0]["functions"].as_array().ok_or("missing functions")?;
    let prefix = format!("{root}/src/");
    let mut result = BTreeMap::new();
    for function in functions {
        let files = function["filenames"]
            .as_array()
            .ok_or("missing filenames")?;
        if !files
            .iter()
            .any(|file| file.as_str().is_some_and(|s| s.starts_with(&prefix)))
        {
            continue;
        }
        if files.len() != 1 {
            return Err("multi-file function is unsupported".into());
        }
        // Host emulation is outside the daemon's event-dispatch work.
        if files[0]
            .as_str()
            .is_some_and(|s| s.ends_with("/src/kernel/fake.rs"))
        {
            continue;
        }
        let name = function["name"].as_str().ok_or("missing function name")?;
        let regions = function["regions"].as_array().ok_or("missing regions")?;
        for (ordinal, region) in regions.iter().enumerate() {
            let row = region.as_array().ok_or("invalid region")?;
            if row.len() != 8 || row[7] != 0 {
                return Err("unsupported region shape".into());
            }
            let count = row[4].as_u64().ok_or("invalid counter")?;
            let mut mapping = row.clone();
            mapping[4] = json!(0);
            let key = json!([name, files, ordinal, mapping]).to_string();
            if result.insert(key, count).is_some() {
                return Err("duplicate region identity".into());
            }
        }
    }
    if result.is_empty() {
        return Err("empty production mapping".into());
    }
    Ok(result)
}

fn work(before: &Value, after: &Value, root: &str) -> Result<u64> {
    let before = counts(before, root)?;
    let after = counts(after, root)?;
    if !before.keys().eq(after.keys()) {
        return Err("production region mappings differ".into());
    }
    let mut total = 0u64;
    for (key, first) in before {
        let delta = after[&key].checked_sub(first).ok_or("counter decreased")?;
        total = total.checked_add(delta).ok_or("work total overflow")?;
    }
    if total == 0 {
        return Err("no measured production work".into());
    }
    Ok(total)
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 3 {
        return Err("usage: COUNT ROOT BEFORE_JSON AFTER_JSON".into());
    }
    let before = serde_json::from_slice(&fs::read(&args[1])?)?;
    let after = serde_json::from_slice(&fs::read(&args[2])?)?;
    println!(
        "SOURCE_WORK_REGION_EXECUTIONS={}",
        work(&before, &after, &args[0])?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn export(count: u64) -> Value {
        json!({"type":"llvm.coverage.json.export","version":"3.1.0","data":[{
            "functions":[{"name":"function","filenames":["/root/src/file.rs"],
                "regions":[[1,1,2,1,count,0,0,0]]}]
        }]})
    }
    #[test]
    fn counts_real_deltas_and_rejects_empty_or_decreasing_work() {
        assert_eq!(work(&export(10), &export(50), "/root").unwrap(), 40);
        assert!(work(&export(50), &export(10), "/root").is_err());
        assert!(work(&export(10), &export(10), "/root").is_err());
        assert!(work(&export(10), &export(50), "/other").is_err());
    }
    #[test]
    fn rejects_changed_mappings_and_schema() {
        let before = export(10);
        let mut after = export(50);
        after["data"][0]["functions"][0]["regions"][0][2] = json!(3);
        assert!(work(&before, &after, "/root").is_err());
        after = export(50);
        after["version"] = json!("unknown");
        assert!(work(&before, &after, "/root").is_err());
    }
}
