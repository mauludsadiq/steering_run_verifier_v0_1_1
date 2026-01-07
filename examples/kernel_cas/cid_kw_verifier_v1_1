use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use steering_run_verifier::canonical::{canonical_json_string, set_dotpath_string};
use steering_run_verifier::hash::sha256_hex;
use steering_run_verifier::kernel::{
    check_nilpotence, check_trace, laws_check_all_v1_1, Mat, VecF,
};

#[derive(Debug, serde::Serialize)]
struct ErrorOut {
    kind: &'static str,
    error_id: String,
    message: String,
}

impl ErrorOut {
    fn new(error_id: &str, message: &str) -> Self {
        Self {
            kind: "error",
            error_id: error_id.to_string(),
            message: message.to_string(),
        }
    }
}

#[derive(Deserialize)]
struct ArtifactItem {
    cid: String,
    bytes_hash: String,
    media_type: String,
    note: String,
}

#[derive(Deserialize)]
struct Artifacts {
    hash_algo: String,
    items: Vec<ArtifactItem>,
}

#[derive(Deserialize)]
struct Domain {
    domain_name: String,
    domain_version: String,
    schema_cid: String,
    verifier_cid: String,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct Run {
    cid_run: String,
    cid_run_algo: String,
    cid_run_source: String,
    cid_run_field_blank_value: String,
    cid_run_blank_fields: Vec<String>,
}

#[derive(Deserialize)]
struct Space {
    n: usize,
}

#[derive(Deserialize)]
struct Tolerance {
    eps: f64,
}

#[derive(Deserialize)]
struct Projection {
    p: Mat,
}

#[derive(Deserialize)]
struct Descent {
    phi: Mat,
}

#[derive(Deserialize)]
struct Samples {
    x_samples: Vec<VecF>,
}

#[derive(Deserialize)]
#[serde(tag = "kind")]
enum Termination {
    #[serde(rename = "nilpotence_k")]
    NilpotenceK { k: u64 },

    #[serde(rename = "trace")]
    Trace {
        x_trace: Vec<VecF>,
        h_trace: Option<Vec<u64>>,
    },
}

#[derive(Deserialize)]
struct KernelWitness {
    witness_version: String,
    domain: Domain,
    run: Run,
    artifacts: Artifacts,
    space: Space,
    tolerance: Tolerance,
    projection: Projection,
    descent: Descent,
    samples: Samples,
    termination: Termination,
}

fn read_bytes(path: &str) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|e| format!("failed to read {}: {}", path, e))
}

fn cas_path(cas_dir: &str, cid: &str) -> String {
    format!("{}/{}", cas_dir.trim_end_matches('/'), cid)
}

#[allow(dead_code)]
fn build_artifact_index(items: &[ArtifactItem]) -> BTreeMap<String, ArtifactItem> {
    let mut m = BTreeMap::new();
    for it in items {
        m.insert(
            it.cid.clone(),
            ArtifactItem {
                cid: it.cid.clone(),
                bytes_hash: it.bytes_hash.clone(),
                media_type: it.media_type.clone(),
                note: it.note.clone(),
            },
        );
    }
    m
}

fn verify_artifacts(cas_dir: &str, artifacts: &Artifacts) -> Result<(), String> {
    if artifacts.hash_algo != "sha256" {
        return Err("ARTIFACT_HASH_ALGO_UNSUPPORTED".to_string());
    }

    for it in &artifacts.items {
        let _ = &it.media_type;
        let _ = &it.note;

        let p = cas_path(cas_dir, &it.cid);
        let b = read_bytes(&p).map_err(|_| format!("ARTIFACT_MISSING failed to read {}", p))?;
        let h = sha256_hex(&b);
        if h != it.bytes_hash {
            return Err(format!(
                "ARTIFACT_HASH_MISMATCH cid={} expected_hash={} got_hash={}",
                it.cid, it.bytes_hash, h
            ));
        }
    }
    Ok(())
}

fn collect_cid_fields(w: &KernelWitness) -> BTreeSet<String> {
    let mut s = BTreeSet::new();
    s.insert(w.domain.schema_cid.clone());
    s.insert(w.domain.verifier_cid.clone());
    s
}

fn verify_cid_reference_closure(w: &KernelWitness) -> Result<(), String> {
    let declared: BTreeSet<String> = w.artifacts.items.iter().map(|it| it.cid.clone()).collect();
    let referenced = collect_cid_fields(w);

    let mut missing: Vec<String> = referenced
        .into_iter()
        .filter(|c| !declared.contains(c))
        .collect();
    missing.sort();

    if !missing.is_empty() {
        return Err(format!("CID_REFERENCE_CLOSURE missing_cids={:?}", missing));
    }

    let mut seen = BTreeSet::new();
    let mut dups = BTreeSet::new();
    for it in &w.artifacts.items {
        if !seen.insert(it.cid.clone()) {
            dups.insert(it.cid.clone());
        }
    }
    if !dups.is_empty() {
        let mut v: Vec<String> = dups.into_iter().collect();
        v.sort();
        return Err(format!("CID_REFERENCE_CLOSURE duplicate_cids={:?}", v));
    }

    Ok(())
}

fn compute_cid_run_from_value(
    v: &Value,
    blank_paths: &[String],
    blank_value: &str,
) -> Result<String, String> {
    let mut vv = v.clone();
    for p in blank_paths {
        set_dotpath_string(&mut vv, p, blank_value)
            .map_err(|e| format!("CID_RUN_BLANK_FAILED path={} err={}", p, e))?;
    }
    let canon = canonical_json_string(&vv).map_err(|e| format!("CANON_FAILED {}", e))?;
    Ok(sha256_hex(canon.as_bytes()))
}

fn compute_cid_run_from_path(
    path: &str,
    blank_paths: &[String],
    blank_value: &str,
) -> Result<String, String> {
    let s = fs::read_to_string(path).map_err(|e| format!("WITNESS_READ_FAILED {}", e))?;
    let v: Value = serde_json::from_str(&s).map_err(|e| format!("WITNESS_JSON_INVALID {}", e))?;
    compute_cid_run_from_value(&v, blank_paths, blank_value)
}

fn verify_cid_run(path: &str, w: &KernelWitness) -> Result<String, String> {
    if w.run.cid_run_algo != "sha256" {
        return Err("CID_RUN_ALGO_UNSUPPORTED".to_string());
    }
    if !w.run.cid_run_field_blank_value.is_empty() {
        return Err("CID_RUN_BLANK_VALUE_NOT_EMPTY".to_string());
    }
    if w.run.cid_run_blank_fields != vec!["run.cid_run".to_string()] {
        return Err("CID_RUN_BLANK_FIELDS_NOT_PINNED".to_string());
    }

    let recomputed = compute_cid_run_from_path(
        path,
        &w.run.cid_run_blank_fields,
        &w.run.cid_run_field_blank_value,
    )?;
    if recomputed != w.run.cid_run {
        return Err(format!(
            "CID_RUN_MISMATCH claimed={} recomputed={}",
            w.run.cid_run, recomputed
        ));
    }
    Ok(recomputed)
}

fn parse_mat(m: &Mat, n: usize) -> Result<(), String> {
    if m.len() != n {
        return Err(format!("DIM_FAIL mat rows={} expected={}", m.len(), n));
    }
    for (i, row) in m.iter().enumerate() {
        if row.len() != n {
            return Err(format!(
                "DIM_FAIL mat row={} cols={} expected={}",
                i,
                row.len(),
                n
            ));
        }
    }
    Ok(())
}

fn verify_kernel_math(w: &KernelWitness) -> Result<(), String> {
    let n = w.space.n;
    let eps = w.tolerance.eps;

    parse_mat(&w.projection.p, n)?;
    parse_mat(&w.descent.phi, n)?;

    laws_check_all_v1_1(&w.projection.p, &w.descent.phi, &w.samples.x_samples, eps)
        .map_err(|e| format!("KERNEL_LAWS_FAIL {}", e))?;

    match &w.termination {
        Termination::NilpotenceK { k } => {
            check_nilpotence(&w.descent.phi, *k, eps)
                .map_err(|e| format!("KERNEL_TERM_FAIL {}", e))?;
        }
        Termination::Trace { x_trace, h_trace } => {
            check_trace(&w.descent.phi, x_trace, h_trace.as_deref(), eps)
                .map_err(|e| format!("KERNEL_TERM_FAIL {}", e))?;
        }
    }

    Ok(())
}

fn cmd_verify(witness_path: &str, cas_dir: &str, print_ok: bool) -> Result<(), ErrorOut> {
    let s = fs::read_to_string(witness_path)
        .map_err(|e| ErrorOut::new("WITNESS_READ_FAILED", &format!("{}", e)))?;
    let v: Value = serde_json::from_str(&s)
        .map_err(|e| ErrorOut::new("WITNESS_JSON_INVALID", &format!("{}", e)))?;
    let w: KernelWitness = serde_json::from_value(v.clone())
        .map_err(|e| ErrorOut::new("WITNESS_STRUCT_INVALID", &format!("{}", e)))?;

    if w.witness_version != "1.1" {
        return Err(ErrorOut::new("WITNESS_VERSION_UNSUPPORTED", "expected 1.1"));
    }
    if w.domain.domain_name != "kernel_witness" || w.domain.domain_version != "1.1" {
        return Err(ErrorOut::new(
            "DOMAIN_UNSUPPORTED",
            "expected kernel_witness 1.1",
        ));
    }

    verify_cid_reference_closure(&w).map_err(|e| ErrorOut::new("CID_REFERENCE_CLOSURE", &e))?;

    verify_artifacts(cas_dir, &w.artifacts).map_err(|e| {
        if e.starts_with("ARTIFACT_MISSING") {
            ErrorOut::new("ARTIFACT_MISSING", &e)
        } else if e.starts_with("ARTIFACT_HASH_MISMATCH") {
            ErrorOut::new("ARTIFACT_HASH_MISMATCH", &e)
        } else {
            ErrorOut::new("ARTIFACT_INVALID", &e)
        }
    })?;

    let cid_run =
        verify_cid_run(witness_path, &w).map_err(|e| ErrorOut::new("CID_RUN_MISMATCH", &e))?;

    verify_kernel_math(&w).map_err(|e| ErrorOut::new("KERNEL_MATH_INVALID", &e))?;
    verify_termination_certificate(&w)
        .map_err(|e| ErrorOut::new("TERMINATION_CERT_INVALID", &e))?;
    let _out = serde_json::json!({ "ok": true, "cid_run": cid_run });
    if print_ok {
        let tr = tr_build_verify_transcript(witness_path, cas_dir, &w)
            .map_err(|e| ErrorOut::new("PRINT_TRANSCRIPT_FAILED", &e))?;
        println!("{}", serde_json::to_string_pretty(&tr).unwrap());
    }
    Ok(())
}

fn cmd_cid_run(witness_path: &str) -> Result<(), ErrorOut> {
    let s = fs::read_to_string(witness_path)
        .map_err(|e| ErrorOut::new("WITNESS_READ_FAILED", &format!("{}", e)))?;
    let v: Value = serde_json::from_str(&s)
        .map_err(|e| ErrorOut::new("WITNESS_JSON_INVALID", &format!("{}", e)))?;
    let w: KernelWitness = serde_json::from_value(v.clone())
        .map_err(|e| ErrorOut::new("WITNESS_STRUCT_INVALID", &format!("{}", e)))?;

    let cid_run = compute_cid_run_from_value(
        &v,
        &w.run.cid_run_blank_fields,
        &w.run.cid_run_field_blank_value,
    )
    .map_err(|e| ErrorOut::new("CID_RUN_FAILED", &e))?;

    let out = serde_json::json!({ "cid_run": cid_run });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
    Ok(())
}

// -----------------------------
// verify --print-ok transcript
// -----------------------------

#[derive(serde::Serialize)]
struct VerifyTranscript {
    projection_p: Mat,
    descent_phi: Mat,
    derived: serde_json::Value,
    ok: bool,

    cid_run_expected: String,
    cid_run_computed: String,
    cid_run_matches: bool,

    witness: WitnessInfo,
    artifacts: ArtifactsReport,
    laws_v1_1: Vec<LawCheck>,
    termination: TerminationReport,
}

#[derive(serde::Serialize)]
struct WitnessInfo {
    witness_version: String,
    domain_name: String,
    domain_version: String,
    n: usize,
    eps: f64,

    cid_run_algo: String,
    cid_run_source: String,
    cid_run_blank_fields: Vec<String>,
    cid_run_field_blank_value: String,
}

#[derive(serde::Serialize)]
struct ArtifactsReport {
    hash_algo: String,
    items: Vec<ArtifactCheck>,
}

#[derive(serde::Serialize)]
struct ArtifactCheck {
    cid: String,
    media_type: String,
    note: String,
    cas_path: String,
    expected_hash: String,
    computed_hash: String,
    hash_matches: bool,
}

#[derive(serde::Serialize)]
struct LawCheck {
    lhs: Option<Mat>,
    rhs: Option<Mat>,
    diff: Option<Mat>,
    name: String,
    ok: bool,
    eps: f64,
    err_inf: f64,
    note: String,
}

#[derive(serde::Serialize)]
#[serde(tag = "kind")]
enum TerminationReport {
    #[serde(rename = "nilpotence_k")]
    NilpotenceK {
        k: u64,
        eps: f64,
        ok: bool,
        phi_pow_k_err_inf: f64,
        phi_pow_k_minus_1_err_inf: Option<f64>,
        note: String,
    },

    #[serde(rename = "trace")]
    Trace {
        eps: f64,
        ok: bool,
        steps: usize,
        residuals_inf: Vec<f64>,
        h_trace: Option<Vec<u64>>,
        h_strictly_decreasing: Option<bool>,
        note: String,
    },
}

// ---------- matrix helpers (Mat = Vec<Vec<f64>>) ----------

fn tr_mat_dims(a: &Mat) -> (usize, usize) {
    let r = a.len();
    let c = if r == 0 { 0 } else { a[0].len() };
    (r, c)
}

#[allow(clippy::needless_range_loop)]
fn tr_mat_mul(a: &Mat, b: &Mat) -> Result<Mat, String> {
    let (ar, ac) = tr_mat_dims(a);
    let (br, bc) = tr_mat_dims(b);
    if ac != br {
        return Err(format!(
            "mat_mul dim mismatch: a is {}x{}, b is {}x{}",
            ar, ac, br, bc
        ));
    }
    let mut out = vec![vec![0.0f64; bc]; ar];
    for i in 0..ar {
        for k in 0..ac {
            let aik = a[i][k];
            for j in 0..bc {
                out[i][j] += aik * b[k][j];
            }
        }
    }
    Ok(out)
}

fn tr_mat_sub(a: &Mat, b: &Mat) -> Result<Mat, String> {
    let (ar, ac) = tr_mat_dims(a);
    let (br, bc) = tr_mat_dims(b);
    if ar != br || ac != bc {
        return Err(format!(
            "mat_sub dim mismatch: a is {}x{}, b is {}x{}",
            ar, ac, br, bc
        ));
    }
    let mut out = vec![vec![0.0f64; ac]; ar];
    for i in 0..ar {
        for j in 0..ac {
            out[i][j] = a[i][j] - b[i][j];
        }
    }
    Ok(out)
}

fn tr_mat_norm_inf(a: &Mat) -> f64 {
    let mut m = 0.0f64;
    for row in a {
        for &x in row {
            let ax = x.abs();
            if ax > m {
                m = ax;
            }
        }
    }
    m
}

#[allow(clippy::needless_range_loop)]
fn tr_mat_pow(phi: &Mat, k: u64) -> Result<Mat, String> {
    let (n, m) = tr_mat_dims(phi);
    if n != m {
        return Err(format!("mat_pow requires square matrix, got {}x{}", n, m));
    }
    // identity
    let mut out = vec![vec![0.0f64; n]; n];
    for i in 0..n {
        out[i][i] = 1.0;
    }
    if k == 0 {
        return Ok(out);
    }
    let mut base = phi.clone();
    let mut e = k;
    while e > 0 {
        if (e & 1) == 1 {
            out = tr_mat_mul(&out, &base)?;
        }
        e >>= 1;
        if e > 0 {
            base = tr_mat_mul(&base, &base)?;
        }
    }
    Ok(out)
}

fn tr_vec_norm_inf(v: &VecF) -> f64 {
    v.iter().map(|x| x.abs()).fold(0.0, f64::max)
}

#[allow(clippy::needless_range_loop)]
fn tr_mat_vec_mul(a: &Mat, x: &VecF) -> Result<VecF, String> {
    let (ar, ac) = tr_mat_dims(a);
    if ac != x.len() {
        return Err(format!(
            "mat_vec_mul dim mismatch: a is {}x{}, x is {}",
            ar,
            ac,
            x.len()
        ));
    }
    let mut y = vec![0.0f64; ar];
    for i in 0..ar {
        let mut s = 0.0;
        for j in 0..ac {
            s += a[i][j] * x[j];
        }
        y[i] = s;
    }
    Ok(y)
}

fn tr_vec_sub(a: &VecF, b: &VecF) -> Result<VecF, String> {
    if a.len() != b.len() {
        return Err(format!(
            "vec_sub dim mismatch: a={}, b={}",
            a.len(),
            b.len()
        ));
    }
    Ok(a.iter().zip(b.iter()).map(|(x, y)| x - y).collect())
}

// ---------- transcript builders ----------

fn tr_build_artifacts_report(
    cas_dir: &str,
    artifacts: &Artifacts,
) -> Result<ArtifactsReport, String> {
    if artifacts.hash_algo != "sha256" {
        return Err("ARTIFACT_HASH_ALGO_UNSUPPORTED".to_string());
    }
    let mut out = Vec::new();
    for it in &artifacts.items {
        let p = cas_path(cas_dir, &it.cid);
        let bytes = read_bytes(&p)?;
        let computed = sha256_hex(&bytes);
        let matches = computed == it.bytes_hash;
        out.push(ArtifactCheck {
            cid: it.cid.clone(),
            media_type: it.media_type.clone(),
            note: it.note.clone(),
            cas_path: p,
            expected_hash: it.bytes_hash.clone(),
            computed_hash: computed,
            hash_matches: matches,
        });
        if !matches {
            return Err(format!(
                "hash mismatch for {} (CAS file {})",
                it.cid,
                out.last().unwrap().cas_path
            ));
        }
    }
    Ok(ArtifactsReport {
        hash_algo: artifacts.hash_algo.clone(),
        items: out,
    })
}

fn tr_build_termination_report(w: &KernelWitness) -> Result<TerminationReport, String> {
    let eps = w.tolerance.eps;

    match &w.termination {
        Termination::NilpotenceK { k } => {
            // hard check (kernel.rs)
            check_nilpotence(&w.descent.phi, *k, eps)?;

            // metrics
            let phi_k = tr_mat_pow(&w.descent.phi, *k)?;
            let err_k = tr_mat_norm_inf(&phi_k);

            let err_km1 = if *k >= 1 {
                let phi_km1 = tr_mat_pow(&w.descent.phi, *k - 1)?;
                Some(tr_mat_norm_inf(&phi_km1))
            } else {
                None
            };

            Ok(TerminationReport::NilpotenceK {
                k: *k,
                eps,
                ok: true,
                phi_pow_k_err_inf: err_k,
                phi_pow_k_minus_1_err_inf: err_km1,
                note: "checked Phi^k ≈ 0; reports ||Phi^k||_∞ and ||Phi^(k-1)||_∞".to_string(),
            })
        }

        Termination::Trace { x_trace, h_trace } => {
            // hard check (kernel.rs expects Option<&[u64]>)
            let h_slice: Option<&[u64]> = h_trace.as_ref().map(|v| &v[..]);
            check_trace(&w.descent.phi, x_trace, h_slice, eps)?;

            if x_trace.len() < 2 {
                return Err("trace termination requires at least 2 vectors".to_string());
            }

            // metrics: r_t = x_{t+1} - Phi x_t
            let mut residuals = Vec::new();
            for t in 0..(x_trace.len() - 1) {
                let pred = tr_mat_vec_mul(&w.descent.phi, &x_trace[t])?;
                let r = tr_vec_sub(&x_trace[t + 1], &pred)?;
                residuals.push(tr_vec_norm_inf(&r));
            }

            let h_decreasing = h_trace.as_ref().map(|hs| {
                if hs.len() < 2 {
                    return true;
                }
                for t in 0..(hs.len() - 1) {
                    if hs[t + 1] >= hs[t] {
                        return false;
                    }
                }
                true
            });

            Ok(TerminationReport::Trace {
                eps,
                ok: true,
                steps: x_trace.len() - 1,
                residuals_inf: residuals,
                h_trace: h_trace.clone(),
                h_strictly_decreasing: h_decreasing,
                note: "checked x_{t+1} ≈ Phi x_t; reports residual ||r_t||_∞; checks h strict decrease if provided".to_string(),
            })
        }
    }
}

fn tr_ok_term(t: &TerminationReport) -> bool {
    match t {
        TerminationReport::NilpotenceK { ok, .. } => *ok,
        TerminationReport::Trace { ok, .. } => *ok,
    }
}

fn tr_build_verify_transcript(
    witness_path: &str,
    cas_dir: &str,
    w: &KernelWitness,
) -> Result<VerifyTranscript, String> {
    // cid_run
    let cid_run_computed = compute_cid_run_from_path(
        witness_path,
        &w.run.cid_run_blank_fields,
        &w.run.cid_run_field_blank_value,
    )?;
    let cid_run_expected = w.run.cid_run.clone();
    let cid_run_matches = cid_run_expected == cid_run_computed;

    // laws (numeric errors)
    let eps = w.tolerance.eps;
    let p = &w.projection.p;
    let phi = &w.descent.phi;

    let mut laws = Vec::<LawCheck>::new();

    // P^2 = P
    let p2 = tr_mat_mul(p, p)?;
    let p2_minus_p = tr_mat_sub(&p2, p)?;
    let err_p_idem = tr_mat_norm_inf(&p2_minus_p);
    laws.push(LawCheck {
        name: "P^2 = P (idempotence)".to_string(),
        ok: err_p_idem <= eps,
        eps,
        err_inf: err_p_idem,
        lhs: Some(p2.clone()),
        rhs: Some(p.clone()),
        diff: Some(p2_minus_p.clone()),
        note: "computed ||P·P − P||_∞".to_string(),
    });

    // Phi^2 = 0
    let phi2 = tr_mat_mul(phi, phi)?;
    let err_phi2 = tr_mat_norm_inf(&phi2);
    laws.push(LawCheck {
        name: "Phi^2 = 0 (nilpotence order-2)".to_string(),
        ok: err_phi2 <= eps,
        eps,
        err_inf: err_phi2,
        lhs: Some(phi2.clone()),
        rhs: Some(vec![vec![0.0f64; w.space.n]; w.space.n]),
        diff: None,
        note: "computed ||Phi·Phi||_∞".to_string(),
    });

    // P·Phi = 0
    let pphi = tr_mat_mul(p, phi)?;
    let err_pphi = tr_mat_norm_inf(&pphi);
    laws.push(LawCheck {
        name: "P·Phi = 0 (compatibility)".to_string(),
        ok: err_pphi <= eps,
        eps,
        err_inf: err_pphi,
        lhs: Some(pphi.clone()),
        rhs: Some(vec![vec![0.0f64; w.space.n]; w.space.n]),
        diff: None,
        note: "computed ||P·Phi||_∞".to_string(),
    });

    // Phi·P = 0
    let phip = tr_mat_mul(phi, p)?;
    let err_phip = tr_mat_norm_inf(&phip);
    laws.push(LawCheck {
        name: "Phi·P = 0 (compatibility)".to_string(),
        ok: err_phip <= eps,
        eps,
        err_inf: err_phip,
        lhs: Some(phip.clone()),
        rhs: Some(vec![vec![0.0f64; w.space.n]; w.space.n]),
        diff: None,
        note: "computed ||Phi·P||_∞".to_string(),
    });

    // artifacts + termination
    let artifacts = tr_build_artifacts_report(cas_dir, &w.artifacts)?;
    let termination = tr_build_termination_report(w)?;

    let witness = WitnessInfo {
        witness_version: w.witness_version.clone(),
        domain_name: w.domain.domain_name.clone(),
        domain_version: w.domain.domain_version.clone(),
        n: w.space.n,
        eps: w.tolerance.eps,

        cid_run_algo: w.run.cid_run_algo.clone(),
        cid_run_source: w.run.cid_run_source.clone(),
        cid_run_blank_fields: w.run.cid_run_blank_fields.clone(),
        cid_run_field_blank_value: w.run.cid_run_field_blank_value.clone(),
    };

    let ok = cid_run_matches
        && laws.iter().all(|c| c.ok)
        && tr_ok_term(&termination)
        && artifacts.items.iter().all(|x| x.hash_matches);

    Ok(VerifyTranscript {
        projection_p: w.projection.p.clone(),
        descent_phi: w.descent.phi.clone(),
        derived: serde_json::json!({}),
        ok,
        cid_run_expected,
        cid_run_computed,
        cid_run_matches,
        witness,
        artifacts,
        laws_v1_1: laws,
        termination,
    })
}

fn usage() {
    eprintln!("usage:");
    eprintln!("  kernel_witness_verifier verify --witness <path> --cas-dir <dir> [--print-ok]");
    eprintln!("  kernel_witness_verifier cid-run --witness <path>");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        usage();
        std::process::exit(2);
    }

    let sub = args[1].as_str();

    if sub == "cid-run" {
        let mut witness_path: Option<String> = None;
        let mut i = 2;
        while i < args.len() {
            if args[i].as_str() == "--witness" {
                i += 1;
                witness_path = args.get(i).cloned();
            }
            i += 1;
        }
        let wp = match witness_path {
            Some(x) => x,
            None => {
                usage();
                std::process::exit(2);
            }
        };
        if let Err(e) = cmd_cid_run(&wp) {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!(e)).unwrap()
            );
            std::process::exit(1);
        }
        return;
    }

    if sub == "verify" {
        let mut witness_path: Option<String> = None;
        let mut cas_dir: Option<String> = None;
        let mut print_ok = false;

        let mut i = 2;
        while i < args.len() {
            let a = args[i].as_str();
            if a == "--witness" {
                i += 1;
                witness_path = args.get(i).cloned();
            } else if a == "--cas-dir" {
                i += 1;
                cas_dir = args.get(i).cloned();
            } else if a == "--print-ok" {
                print_ok = true;
            }
            i += 1;
        }

        let wp = match witness_path {
            Some(x) => x,
            None => {
                usage();
                std::process::exit(2);
            }
        };
        let cd = match cas_dir {
            Some(x) => x,
            None => {
                usage();
                std::process::exit(2);
            }
        };

        if let Err(e) = cmd_verify(&wp, &cd, print_ok) {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!(e)).unwrap()
            );
            std::process::exit(1);
        }
        return;
    }

    usage();
    std::process::exit(2);
}

fn verify_termination_certificate(w: &KernelWitness) -> Result<(), String> {
    let eps = w.tolerance.eps;

    match &w.termination {
        Termination::NilpotenceK { k } => {
            check_nilpotence(&w.descent.phi, *k, eps)?;
            Ok(())
        }
        Termination::Trace { x_trace, h_trace } => {
            check_trace(
                &w.descent.phi,
                x_trace,
                h_trace.as_ref().map(|v| v.as_slice()),
                eps,
            )?;
            Ok(())
        }
    }
}

#[derive(serde::Serialize)]
#[allow(dead_code)]
struct DerivedMats {
    p2: Mat,
    phi2: Mat,
    p_phi: Mat,
    phi_p: Mat,
}
