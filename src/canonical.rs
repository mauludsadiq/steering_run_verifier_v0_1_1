use anyhow::{anyhow, Result};
use serde_json::{Map, Value};

/// Recursively sort all JSON object keys lexicographically and return a new Value.
pub fn canonicalize_value(v: &Value) -> Value {
    match v {
        Value::Object(obj) => {
            let mut keys: Vec<&String> = obj.keys().collect();
            keys.sort();

            let mut out: Map<String, Value> = Map::new();
            for k in keys {
                let vv = obj.get(k).unwrap();
                out.insert(k.clone(), canonicalize_value(vv));
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(canonicalize_value).collect()),
        _ => v.clone(),
    }
}

/// Canonical JSON string: UTF-8, no ws, object keys sorted. Arrays preserved.
pub fn canonical_json_string(v: &Value) -> Result<String> {
    let canon = canonicalize_value(v);
    serde_json::to_string(&canon).map_err(|e| anyhow!("canonical json stringify failed: {e}"))
}

/// Set a dotpath (e.g. "run.cid_run") to a JSON string value.
/// Only supports dotpaths consisting of object keys (no array indices).
pub fn set_dotpath_string(root: &mut Value, dotpath: &str, new_val: &str) -> Result<()> {
    let mut cur = root;
    let parts: Vec<&str> = dotpath.split('.').collect();
    if parts.is_empty() {
        return Err(anyhow!("empty dotpath"));
    }
    for (i, key) in parts.iter().enumerate() {
        let last = i == parts.len() - 1;
        match cur {
            Value::Object(map) => {
                if last {
                    map.insert((*key).to_string(), Value::String(new_val.to_string()));
                    return Ok(());
                }
                cur = map
                    .get_mut(*key)
                    .ok_or_else(|| anyhow!("dotpath missing object key: {dotpath}"))?;
            }
            _ => return Err(anyhow!("dotpath did not traverse object at: {dotpath}")),
        }
    }
    Ok(())
}
