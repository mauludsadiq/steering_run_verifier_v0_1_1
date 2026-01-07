use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::env;
use std::fs;

use sha2::{Digest, Sha256};

use steering_run_verifier::canonical::{canonical_json_string, set_dotpath_string};
use steering_run_verifier::kernel::{
    check_kernel_axioms, mat_apply, mat_dim, termination_height_under_phi, vec_dim, Mat, VecI,
};

#[derive(Debug, Serialize)]
struct OutOk {
    ok: bool,
    cid_run: String,
}

#[derive(Debug, Serialize)]
struct OutErr {
    kind: String,
    error_id: String,
    message: String,
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactItem {
    cid: String,
    bytes_hash: String,
    media_type: String,
    note: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifacts {
    hash_algo: String,
    items: Vec<ArtifactItem>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Domain {
    domain_name: String,
    domain_version: String,
    schema_cid: String,
    verifier_cid: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Run {
    cid_run: String,
    cid_run_algo: String,
    cid_run_field_blank_value: String,
    cid_run_blank_fields: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Space {
    dim: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entropy {
    kind: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Sample {
    x0: VecI,
    expect_height: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Kernel {
    space: Space,
    projection_P: Mat,
    descent_Phi: Mat,
    nilpotence_k: usize,
    entropy: Entropy,
    samples: Vec<Sample>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KernelWitness {
    witness_version: String,
    domain: Domain,
    run: Run,
    artifacts: Artifacts,
    kernel: Kernel,
}

fn read_bytes(path: &str) -> Result<Vec<u8>> {
    Ok(fs::read(path)?)
}

fn verify_artifacts(w: &KernelWitness, cas_dir: &str) -> Result<()> {
    if w.artifacts.hash_algo != "sha256" {
        return Err(anyhow!("artifacts.hash_algo must be sha256"));
    }
    for it in &w.artifacts.items {
        let p = format!("{}/{}", cas_dir, it.cid);
        let b = read_bytes(&p).map_err(|e| anyhow!("failed to read {}: {}", p, e))?;
        let got = sha256_hex(&b);
        if got != it.bytes_hash {
            return Err(anyhow!(
                "ARTIFACT_HASH_MISMATCH cid={} expected_hash={} got_hash={}",
                it.cid,
                it.bytes_hash,
                got
            ));
        }
    }
    Ok(())
}

fn compute_cid_run_json(
    mut v: Value,
    blank_fields: &[String],
    blank_value: &str,
) -> Result<String> {
    for dp in blank_fields {
        set_dotpath_string(&mut v, dp, blank_value)?;
    }
    let canon = canonical_json_string(&v)?;
    Ok(sha256_hex(canon.as_bytes()))
}

fn verify_cid_run(witness_path: &str, w: &KernelWitness) -> Result<String> {
    if w.run.cid_run_algo != "sha256" {
        return Err(anyhow!("run.cid_run_algo must be sha256"));
    }
    if w.run.cid_run_blank_fields != vec!["run.cid_run".to_string()] {
        return Err(anyhow!(
            "run.cid_run_blank_fields must equal [\"run.cid_run\"] in v1.1"
        ));
    }
    if w.run.cid_run_field_blank_value != "" {
        return Err(anyhow!(
            "run.cid_run_field_blank_value must be \"\" in v1.1"
        ));
    }

    let bytes = read_bytes(witness_path)?;
    let v: Value = serde_json::from_slice(&bytes)?;
    let recomputed = compute_cid_run_json(
        v,
        &w.run.cid_run_blank_fields,
        &w.run.cid_run_field_blank_value,
    )?;
    if recomputed != w.run.cid_run {
        return Err(anyhow!(
            "CID_RUN_MISMATCH claimed={} recomputed={}",
            w.run.cid_run,
            recomputed
        ));
    }
    Ok(recomputed)
}

fn verify_kernel(w: &KernelWitness) -> Result<()> {
    if w.witness_version != "1.1" {
        return Err(anyhow!("witness_version must be 1.1"));
    }
    if w.domain.domain_name != "kernel" || w.domain.domain_version != "1.1" {
        return Err(anyhow!("domain must be kernel 1.1"));
    }
    if w.kernel.entropy.kind != "termination_height_under_Phi" {
        return Err(anyhow!(
            "kernel.entropy.kind must be termination_height_under_Phi"
        ));
    }

    let n = w.kernel.space.dim;
    if mat_dim(&w.kernel.projection_P)? != n {
        return Err(anyhow!("projection_P dim must equal space.dim"));
    }
    if mat_dim(&w.kernel.descent_Phi)? != n {
        return Err(anyhow!("descent_Phi dim must equal space.dim"));
    }

    check_kernel_axioms(
        &w.kernel.projection_P,
        &w.kernel.descent_Phi,
        w.kernel.nilpotence_k,
    )?;

    for s in &w.kernel.samples {
        vec_dim(&s.x0, n)?;
        let h = termination_height_under_phi(&w.kernel.descent_Phi, w.kernel.nilpotence_k, &s.x0)?;
        if h != s.expect_height {
            return Err(anyhow!(
                "SAMPLE_HEIGHT_MISMATCH expected={} got={}",
                s.expect_height,
                h
            ));
        }
        if h > 0 {
            let x1 = mat_apply(&w.kernel.descent_Phi, &s.x0)?;
            let h1 =
                termination_height_under_phi(&w.kernel.descent_Phi, w.kernel.nilpotence_k, &x1)?;
            if h1 >= h {
                return Err(anyhow!(
                    "ENTROPY_NOT_STRICTLY_DECREASING H(x)={} H(Phi(x))={}",
                    h,
                    h1
                ));
            }
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        return Err(anyhow!(
            "usage: kernel_witness_verifier verify --witness <path> --cas-dir <dir> [--print-ok]"
        ));
    }
    if args[1] != "verify" {
        return Err(anyhow!("only subcommand supported: verify"));
    }

    let mut witness_path: Option<String> = None;
    let mut cas_dir: Option<String> = None;
    let mut print_ok = false;

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--witness" => {
                i += 1;
                witness_path = args.get(i).cloned();
            }
            "--cas-dir" => {
                i += 1;
                cas_dir = args.get(i).cloned();
            }
            "--print-ok" => {
                print_ok = true;
            }
            _ => {}
        }
        i += 1;
    }

    let witness_path = witness_path.ok_or_else(|| anyhow!("missing --witness"))?;
    let cas_dir = cas_dir.ok_or_else(|| anyhow!("missing --cas-dir"))?;

    let bytes = fs::read(&witness_path).map_err(|e| {
        let out = OutErr {
            kind: "error".to_string(),
            error_id: "WITNESS_READ_FAILED".to_string(),
            message: format!("failed to read {}: {}", witness_path, e),
        };
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
        e
    })?;

    let w: KernelWitness = match serde_json::from_slice(&bytes) {
        Ok(x) => x,
        Err(e) => {
            let out = OutErr {
                kind: "error".to_string(),
                error_id: "WITNESS_PARSE_FAILED".to_string(),
                message: format!("failed to parse witness JSON: {}", e),
            };
            println!("{}", serde_json::to_string_pretty(&out)?);
            return Ok(());
        }
    };

    if let Err(e) = verify_kernel(&w) {
        let out = OutErr {
            kind: "error".to_string(),
            error_id: "KERNEL_CHECK_FAILED".to_string(),
            message: e.to_string(),
        };
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    if let Err(e) = verify_artifacts(&w, &cas_dir) {
        let out = OutErr {
            kind: "error".to_string(),
            error_id: "ARTIFACT_CHECK_FAILED".to_string(),
            message: e.to_string(),
        };
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    let cid_run = match verify_cid_run(&witness_path, &w) {
        Ok(x) => x,
        Err(e) => {
            let out = OutErr {
                kind: "error".to_string(),
                error_id: "CID_RUN_MISMATCH".to_string(),
                message: e.to_string(),
            };
            println!("{}", serde_json::to_string_pretty(&out)?);
            return Ok(());
        }
    };

    let out = OutOk { ok: true, cid_run };
    if print_ok || !out.ok {
        println!("{}", serde_json::to_string_pretty(&out)?);
    }
    Ok(())
}
