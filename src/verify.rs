use crate::canonical::{canonical_json_string, canonicalize_value, set_dotpath_string};
use crate::hash::{read_bytes, sha256_hex};
use crate::overlap::{decode_tensor_f32, overlap};
use anyhow::{anyhow, Result};
use jsonschema::JSONSchema;
use regex::Regex;
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeSet, HashMap};
use std::path::Path;

const DEFAULT_SCHEMA: &str = include_str!("../schema/steering_run_witness_v0_1_1.schema.json");

#[derive(Debug, Serialize)]
pub struct VerifyOk {
    pub ok: bool,
    pub cid_run: String,
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum VerifyErr {
    /// CID_REFERENCE_CLOSURE_V0_1_1 (NORMATIVE payload)
    CidReferenceClosure {
        error_id: String,
        missing_cids: Vec<String>,
        duplicate_cids: Vec<String>,
    },

    /// Generic deterministic error payload
    Error { error_id: String, message: String },
}

pub fn verify_path(
    witness_path: &Path,
    cas_dir: &Path,
    schema_override: Option<&Path>,
    allow_rerun_mode: bool,
) -> std::result::Result<VerifyOk, VerifyErr> {
    verify_path_impl(witness_path, cas_dir, schema_override, allow_rerun_mode)
}

fn verify_path_impl(
    witness_path: &Path,
    cas_dir: &Path,
    schema_override: Option<&Path>,
    allow_rerun_mode: bool,
) -> std::result::Result<VerifyOk, VerifyErr> {
    // 0) Load JSON
    let witness_bytes = read_bytes(witness_path).map_err(to_err("WITNESS_READ_FAILED"))?;
    let witness_val: Value =
        serde_json::from_slice(&witness_bytes).map_err(|e| VerifyErr::Error {
            error_id: "WITNESS_JSON_PARSE_FAILED".to_string(),
            message: e.to_string(),
        })?;

    // 1) Schema validation
    validate_schema(&witness_val, schema_override).map_err(|e| VerifyErr::Error {
        error_id: "SCHEMA_VALIDATION_FAILED".to_string(),
        message: e.to_string(),
    })?;

    // 2) cid_run validation
    let claimed_cid_run = get_str(&witness_val, "/run/cid_run")
        .ok_or_else(|| err("SCHEMA_ASSERTION_FAILED", "missing run.cid_run"))?;
    let blank_value = get_str(&witness_val, "/run/cid_run_field_blank_value").ok_or_else(|| {
        err(
            "SCHEMA_ASSERTION_FAILED",
            "missing run.cid_run_field_blank_value",
        )
    })?;

    let blank_fields = get_arr_str(&witness_val, "/run/cid_run_blank_fields").ok_or_else(|| {
        err(
            "SCHEMA_ASSERTION_FAILED",
            "missing run.cid_run_blank_fields",
        )
    })?;

    let mut for_hash = witness_val.clone();
    for dotpath in &blank_fields {
        set_dotpath_string(&mut for_hash, dotpath, &blank_value)
            .map_err(|e| err("CID_RUN_BLANKING_FAILED", &e.to_string()))?;
    }

    let canon = canonicalize_value(&for_hash);
    let canon_str = canonical_json_string(&canon).map_err(to_err("CANONICALIZE_FAILED"))?;
    let recomputed = sha256_hex(canon_str.as_bytes());

    if recomputed != claimed_cid_run {
        return Err(VerifyErr::Error {
            error_id: "CID_RUN_MISMATCH".to_string(),
            message: format!(
                "claimed cid_run does not match recomputed: claimed={}, recomputed={}",
                claimed_cid_run, recomputed
            ),
        });
    }

    // 3) Artifacts index + uniqueness
    let artifacts = get_artifacts(&witness_val).map_err(to_err("SCHEMA_ASSERTION_FAILED"))?;
    let mut cid_to_hash: HashMap<String, String> = HashMap::new();
    let mut duplicates: BTreeSet<String> = BTreeSet::new();
    for (cid, bytes_hash) in &artifacts {
        if cid_to_hash
            .insert(cid.clone(), bytes_hash.clone())
            .is_some()
        {
            duplicates.insert(cid.clone());
        }
    }

    // 4) CID reference closure + lexical validity (NORMATIVE)
    let (missing_cids, duplicate_cids) =
        cid_reference_closure_v0_1_1(&witness_val, &cid_to_hash, &duplicates).map_err(|e| {
            VerifyErr::Error {
                error_id: "CID_REFERENCE_CLOSURE_INTERNAL".to_string(),
                message: e.to_string(),
            }
        })?;

    if !missing_cids.is_empty() || !duplicate_cids.is_empty() {
        return Err(VerifyErr::CidReferenceClosure {
            error_id: "CID_REFERENCE_CLOSURE_V0_1_1".to_string(),
            missing_cids,
            duplicate_cids,
        });
    }

    // 5) Artifact integrity: fetch bytes for each artifact and verify bytes_hash
    for (cid, expected_hash) in &cid_to_hash {
        let path = cas_dir.join(cid);
        let bytes = read_bytes(&path).map_err(to_err("ARTIFACT_MISSING"))?;
        let got = sha256_hex(&bytes);
        if got != *expected_hash {
            return Err(VerifyErr::Error {
                error_id: "ARTIFACT_HASH_MISMATCH".to_string(),
                message: format!(
                    "cid={} expected_hash={} got_hash={}",
                    cid, expected_hash, got
                ),
            });
        }
    }

    // 6) Direction tensor consistency + optional orthogonalization validation
    // Load direction vectors referenced by orthogonalization.ordered_basis
    let ortho = witness_val
        .pointer("/orthogonalization")
        .and_then(|v| v.as_object())
        .ok_or_else(|| err("SCHEMA_ASSERTION_FAILED", "missing orthogonalization"))?;

    let procedure_id = ortho
        .get("procedure_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            err(
                "SCHEMA_ASSERTION_FAILED",
                "missing orthogonalization.procedure_id",
            )
        })?;

    let overlap_def = ortho
        .get("overlap_definition")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            err(
                "SCHEMA_ASSERTION_FAILED",
                "missing orthogonalization.overlap_definition",
            )
        })?;

    let norm_def = ortho
        .get("normalization_definition")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            err(
                "SCHEMA_ASSERTION_FAILED",
                "missing orthogonalization.normalization_definition",
            )
        })?;

    if norm_def != "l2" {
        return Err(err(
            "UNSUPPORTED_NORMALIZATION",
            "only normalization_definition=l2 is supported",
        ));
    }

    let tol = ortho
        .get("tolerance_eps")
        .and_then(|v| v.as_f64())
        .ok_or_else(|| {
            err(
                "SCHEMA_ASSERTION_FAILED",
                "missing orthogonalization.tolerance_eps",
            )
        })?;

    let reported_raw = ortho
        .get("reported_overlap_raw")
        .and_then(|v| v.as_f64())
        .ok_or_else(|| {
            err(
                "SCHEMA_ASSERTION_FAILED",
                "missing orthogonalization.reported_overlap_raw",
            )
        })?;

    let reported_used = ortho
        .get("reported_overlap_used")
        .and_then(|v| v.as_f64())
        .ok_or_else(|| {
            err(
                "SCHEMA_ASSERTION_FAILED",
                "missing orthogonalization.reported_overlap_used",
            )
        })?;

    let basis = ortho
        .get("ordered_basis")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            err(
                "SCHEMA_ASSERTION_FAILED",
                "missing orthogonalization.ordered_basis",
            )
        })?;

    let ordered_basis: Vec<String> = basis
        .iter()
        .map(|x| x.as_str().unwrap_or("").to_string())
        .collect();

    if ordered_basis.len() < 2 {
        return Err(err(
            "SCHEMA_ASSERTION_FAILED",
            "ordered_basis must have >=2",
        ));
    }

    let directions = witness_val
        .pointer("/directions")
        .and_then(|v| v.as_array())
        .ok_or_else(|| err("SCHEMA_ASSERTION_FAILED", "missing directions"))?;

    // Map name -> (cid, dtype, shape)
    let mut dir_map: HashMap<String, (String, String, Vec<usize>)> = HashMap::new();
    for d in directions {
        let name = d
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| err("SCHEMA_ASSERTION_FAILED", "direction missing name"))?;
        let tensor_bytes_cid = d
            .get("tensor_bytes_cid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                err(
                    "SCHEMA_ASSERTION_FAILED",
                    "direction missing tensor_bytes_cid",
                )
            })?;
        let enc = d
            .get("tensor_encoding")
            .and_then(|v| v.as_object())
            .ok_or_else(|| {
                err(
                    "SCHEMA_ASSERTION_FAILED",
                    "direction missing tensor_encoding",
                )
            })?;
        let dtype = enc
            .get("dtype")
            .and_then(|v| v.as_str())
            .ok_or_else(|| err("SCHEMA_ASSERTION_FAILED", "tensor_encoding missing dtype"))?;
        let shape_arr = enc
            .get("shape")
            .and_then(|v| v.as_array())
            .ok_or_else(|| err("SCHEMA_ASSERTION_FAILED", "tensor_encoding missing shape"))?;
        let shape: Vec<usize> = shape_arr
            .iter()
            .map(|x| x.as_u64().unwrap_or(0) as usize)
            .collect();
        dir_map.insert(
            name.to_string(),
            (tensor_bytes_cid.to_string(), dtype.to_string(), shape),
        );

        // Consistency: direction.tensor_bytes_hash must equal the artifact bytes_hash for that cid
        let dir_hash = d
            .get("tensor_bytes_hash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                err(
                    "SCHEMA_ASSERTION_FAILED",
                    "direction missing tensor_bytes_hash",
                )
            })?;

        let artifact_hash = cid_to_hash.get(tensor_bytes_cid).ok_or_else(|| {
            err(
                "SCHEMA_ASSERTION_FAILED",
                "tensor_bytes_cid not declared in artifacts (should be prevented by closure rule)",
            )
        })?;

        if dir_hash != artifact_hash {
            return Err(VerifyErr::Error {
                error_id: "TENSOR_HASH_INCONSISTENT".to_string(),
                message: format!(
                    "direction name={} tensor_bytes_cid={} tensor_bytes_hash={} artifacts.bytes_hash={}",
                    name, tensor_bytes_cid, dir_hash, artifact_hash
                ),
            });
        }
    }

    // Load vectors needed
    let mut vecs: Vec<Vec<f32>> = Vec::new();
    for name in &ordered_basis {
        let (cid, dtype, shape) = dir_map.get(name).ok_or_else(|| {
            err(
                "ORTHOGONALIZATION_MISSING_DIRECTION",
                &format!("ordered_basis references unknown direction name={}", name),
            )
        })?;
        let bytes = read_bytes(&cas_dir.join(cid)).map_err(to_err("ARTIFACT_MISSING"))?;
        let v = decode_tensor_f32(&bytes, dtype, shape)
            .map_err(|e| err("TENSOR_DECODE_FAILED", &format!("name={} {e}", name)))?;
        vecs.push(v);
    }

    // Recompute overlaps
    let raw = overlap(overlap_def, norm_def, &vecs[0], &vecs[1])
        .map_err(|e| err("OVERLAP_COMPUTE_FAILED", &e.to_string()))? as f64;

    let used = match procedure_id {
        "gram_schmidt" | "qr" => {
            let ortho_vecs =
                gram_schmidt(&vecs).map_err(|e| err("ORTHOGONALIZE_FAILED", &e.to_string()))?;
            overlap(overlap_def, norm_def, &ortho_vecs[0], &ortho_vecs[1])
                .map_err(|e| err("OVERLAP_COMPUTE_FAILED", &e.to_string()))?
        }
        _ => {
            return Err(err(
                "UNSUPPORTED_ORTHOGONALIZATION",
                &format!("unsupported procedure_id={}", procedure_id),
            ))
        }
    };

    if (raw as f64 - reported_raw).abs() > tol {
        return Err(VerifyErr::Error {
            error_id: "ORTHOGONALIZATION_MISMATCH".to_string(),
            message: format!(
                "reported_overlap_raw mismatch: reported={} recomputed={} tol={}",
                reported_raw, raw, tol
            ),
        });
    }

    if (used as f64 - reported_used).abs() > tol {
        return Err(VerifyErr::Error {
            error_id: "ORTHOGONALIZATION_MISMATCH".to_string(),
            message: format!(
                "reported_overlap_used mismatch: reported={} recomputed={} tol={}",
                reported_used, used, tol
            ),
        });
    }

    // 7) Metrics verification_mode handling
    let mode = get_str(&witness_val, "/metrics/verification_mode").ok_or_else(|| {
        err(
            "SCHEMA_ASSERTION_FAILED",
            "missing metrics.verification_mode",
        )
    })?;

    match mode.as_str() {
        "hash_only" => {
            // Verify metrics.results_hash matches bytes at results_cid
            let results_cid = get_str(&witness_val, "/metrics/results_cid")
                .ok_or_else(|| err("SCHEMA_ASSERTION_FAILED", "missing metrics.results_cid"))?;
            let expected = get_str(&witness_val, "/metrics/results_hash")
                .ok_or_else(|| err("SCHEMA_ASSERTION_FAILED", "missing metrics.results_hash"))?;
            let bytes =
                read_bytes(&cas_dir.join(&results_cid)).map_err(to_err("ARTIFACT_MISSING"))?;
            let got = sha256_hex(&bytes);
            if got != expected {
                return Err(VerifyErr::Error {
                    error_id: "METRICS_RESULTS_HASH_MISMATCH".to_string(),
                    message: format!(
                        "results_cid={} expected={} got={}",
                        results_cid, expected, got
                    ),
                });
            }
        }
        "rerun_required" => {
            if !allow_rerun_mode {
                return Err(VerifyErr::Error {
                    error_id: "VERIFICATION_MODE_UNSUPPORTED".to_string(),
                    message: "metrics.verification_mode=rerun_required; this verifier build only supports hash_only (use --allow-rerun-mode to accept hash-only behavior)".to_string(),
                });
            }
        }
        _ => {
            return Err(err(
                "SCHEMA_ASSERTION_FAILED",
                &format!("unknown verification_mode={}", mode),
            ))
        }
    }

    Ok(VerifyOk {
        ok: true,
        cid_run: claimed_cid_run,
    })
}

fn validate_schema(instance: &Value, schema_override: Option<&Path>) -> Result<()> {
    let schema_bytes = if let Some(p) = schema_override {
        crate::hash::read_bytes(p)?
    } else {
        DEFAULT_SCHEMA.as_bytes().to_vec()
    };
    let schema_json: Value = serde_json::from_slice(&schema_bytes)?;
    let schema_json_static: &'static Value = Box::leak(Box::new(schema_json));
    let compiled = JSONSchema::options().compile(schema_json_static)?;

    let result = compiled.validate(instance);
    if let Err(errors) = result {
        let mut msgs: Vec<String> = Vec::new();
        for (i, e) in errors.into_iter().enumerate() {
            if i >= 10 {
                msgs.push("...".to_string());
                break;
            }
            msgs.push(format!("{}: {}", e.instance_path, e));
        }
        return Err(anyhow!(msgs.join("\n")));
    }
    Ok(())
}

fn get_str(v: &Value, pointer: &str) -> Option<String> {
    v.pointer(pointer)
        .and_then(|x| x.as_str())
        .map(|s| s.to_string())
}

fn get_arr_str(v: &Value, pointer: &str) -> Option<Vec<String>> {
    let arr = v.pointer(pointer)?.as_array()?;
    Some(
        arr.iter()
            .filter_map(|x| x.as_str().map(|s| s.to_string()))
            .collect(),
    )
}

fn get_artifacts(v: &Value) -> Result<Vec<(String, String)>> {
    let items = v
        .pointer("/artifacts/items")
        .and_then(|x| x.as_array())
        .ok_or_else(|| anyhow!("missing artifacts.items"))?;

    let mut out = Vec::new();
    for it in items {
        let cid = it
            .get("cid")
            .and_then(|x| x.as_str())
            .ok_or_else(|| anyhow!("artifact missing cid"))?;
        let bytes_hash = it
            .get("bytes_hash")
            .and_then(|x| x.as_str())
            .ok_or_else(|| anyhow!("artifact missing bytes_hash"))?;
        out.push((cid.to_string(), bytes_hash.to_string()));
    }
    Ok(out)
}

/// Implements CID_REFERENCE_CLOSURE_V0_1_1 + CID lexical validity addendum.
fn cid_reference_closure_v0_1_1(
    witness: &Value,
    artifact_index: &HashMap<String, String>,
    duplicates: &BTreeSet<String>,
) -> Result<(Vec<String>, Vec<String>)> {
    let cid_re = Regex::new(r"^[A-Za-z0-9._:-]{8,}$")?;

    let mut refs: Vec<String> = Vec::new();

    // Fixed locations
    push_ptr_str(&mut refs, witness, "/domain/schema_cid");
    push_ptr_str(&mut refs, witness, "/domain/verifier_cid");
    push_ptr_str(&mut refs, witness, "/model/weights_cid");
    push_ptr_str(&mut refs, witness, "/tokenizer/tokenizer_cid");
    push_ptr_str(&mut refs, witness, "/prompt_suite/suite_cid");

    // directions[]
    if let Some(ds) = witness.pointer("/directions").and_then(|v| v.as_array()) {
        for d in ds {
            push_obj_str(&mut refs, d, &["construction", "training_data_cid"]);
            push_obj_str(&mut refs, d, &["tensor_bytes_cid"]);
        }
    }

    // metrics
    if let Some(ms) = witness
        .pointer("/metrics/definitions")
        .and_then(|v| v.as_array())
    {
        for m in ms {
            if let Some(cid) = m.get("metric_code_cid").and_then(|v| v.as_str()) {
                refs.push(cid.to_string());
            }
        }
    }
    push_ptr_str(&mut refs, witness, "/metrics/results_cid");

    // outputs (optional)
    if witness.pointer("/outputs").is_some() {
        push_ptr_str(
            &mut refs,
            witness,
            "/outputs/per_prompt_first_token_dist/cid",
        );
        push_ptr_str(&mut refs, witness, "/outputs/per_prompt_generated_text/cid");
        push_ptr_str(&mut refs, witness, "/outputs/per_prompt_logits_digest/cid");
    }

    // Partition into valid/invalid
    let mut c_valid: Vec<String> = Vec::new();
    let mut c_invalid: Vec<String> = Vec::new();
    for c in refs {
        if cid_re.is_match(&c) {
            c_valid.push(c);
        } else {
            c_invalid.push(c);
        }
    }

    let mut missing: BTreeSet<String> = BTreeSet::new();
    for c in c_valid {
        if !artifact_index.contains_key(&c) {
            missing.insert(c);
        }
    }
    for c in c_invalid {
        missing.insert(c);
    }

    let duplicate_vec: Vec<String> = duplicates.iter().cloned().collect();
    Ok((missing.into_iter().collect(), duplicate_vec))
}

fn push_ptr_str(out: &mut Vec<String>, v: &Value, ptr: &str) {
    if let Some(s) = v.pointer(ptr).and_then(|x| x.as_str()) {
        out.push(s.to_string());
    }
}

fn push_obj_str(out: &mut Vec<String>, v: &Value, path: &[&str]) {
    let mut cur = v;
    for (i, p) in path.iter().enumerate() {
        if i == path.len() - 1 {
            if let Some(s) = cur.get(*p).and_then(|x| x.as_str()) {
                out.push(s.to_string());
            }
        } else {
            match cur.get(*p) {
                Some(next) => cur = next,
                None => return,
            }
        }
    }
}

fn gram_schmidt(vecs: &[Vec<f32>]) -> Result<Vec<Vec<f32>>> {
    if vecs.is_empty() {
        return Err(anyhow!("empty basis"));
    }
    let n = vecs[0].len();
    for v in vecs {
        if v.len() != n {
            return Err(anyhow!("basis vectors have different lengths"));
        }
    }

    let mut out: Vec<Vec<f32>> = Vec::new();
    for v in vecs {
        let mut u = v.clone();
        for b in &out {
            // proj of u onto b
            let denom = dot(b, b);
            if denom == 0.0 {
                continue;
            }
            let coeff = dot(&u, b) / denom;
            for i in 0..n {
                u[i] -= coeff * b[i];
            }
        }
        out.push(u);
    }
    Ok(out)
}

fn dot(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b.iter()).map(|(x, y)| x * y).sum()
}

fn to_err(error_id: &'static str) -> impl Fn(anyhow::Error) -> VerifyErr {
    move |e| VerifyErr::Error {
        error_id: error_id.to_string(),
        message: e.to_string(),
    }
}

fn err(error_id: &str, message: &str) -> VerifyErr {
    VerifyErr::Error {
        error_id: error_id.to_string(),
        message: message.to_string(),
    }
}

use sha2::{Digest, Sha256};

fn sha256_hex_bytes(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

pub fn compute_cid_run_for_path(witness_path: &std::path::Path) -> Result<String> {
    let bytes = std::fs::read(witness_path)?;
    let mut v: serde_json::Value = serde_json::from_slice(&bytes)?;

    set_dotpath_string(&mut v, "run.cid_run", "")?;

    let canon = canonical_json_string(&v)?;
    Ok(sha256_hex_bytes(canon.as_bytes()))
}

pub fn write_cid_run_in_place(witness_path: &std::path::Path, cid_run: &str) -> Result<()> {
    let bytes = std::fs::read(witness_path)?;
    let mut v: serde_json::Value = serde_json::from_slice(&bytes)?;

    set_dotpath_string(&mut v, "run.cid_run", cid_run)?;

    let canon = canonical_json_string(&v)?;
    std::fs::write(witness_path, canon.as_bytes())?;
    Ok(())
}

impl std::fmt::Display for VerifyErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for VerifyErr {}
