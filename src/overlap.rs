use anyhow::{anyhow, Result};
use half::{bf16, f16};

pub fn numel(shape: &[usize]) -> Result<usize> {
    let mut n: usize = 1;
    for &d in shape {
        if d == 0 {
            return Err(anyhow!("shape dimension 0"));
        }
        n = n.checked_mul(d).ok_or_else(|| anyhow!("shape overflow"))?;
    }
    Ok(n)
}

pub fn decode_tensor_f32(bytes: &[u8], dtype: &str, shape: &[usize]) -> Result<Vec<f32>> {
    let n = numel(shape)?;
    match dtype {
        "float32" => {
            let expected = n * 4;
            if bytes.len() != expected {
                return Err(anyhow!(
                    "float32 bytes length mismatch: got {}, expected {}",
                    bytes.len(),
                    expected
                ));
            }
            let mut out = Vec::with_capacity(n);
            for chunk in bytes.chunks_exact(4) {
                let arr = [chunk[0], chunk[1], chunk[2], chunk[3]];
                out.push(f32::from_le_bytes(arr));
            }
            Ok(out)
        }
        "float16" => {
            let expected = n * 2;
            if bytes.len() != expected {
                return Err(anyhow!(
                    "float16 bytes length mismatch: got {}, expected {}",
                    bytes.len(),
                    expected
                ));
            }
            let mut out = Vec::with_capacity(n);
            for chunk in bytes.chunks_exact(2) {
                let bits = u16::from_le_bytes([chunk[0], chunk[1]]);
                out.push(f16::from_bits(bits).to_f32());
            }
            Ok(out)
        }
        "bfloat16" => {
            let expected = n * 2;
            if bytes.len() != expected {
                return Err(anyhow!(
                    "bfloat16 bytes length mismatch: got {}, expected {}",
                    bytes.len(),
                    expected
                ));
            }
            let mut out = Vec::with_capacity(n);
            for chunk in bytes.chunks_exact(2) {
                let bits = u16::from_le_bytes([chunk[0], chunk[1]]);
                out.push(bf16::from_bits(bits).to_f32());
            }
            Ok(out)
        }
        _ => Err(anyhow!("unsupported dtype: {dtype}")),
    }
}

fn l2_norm(v: &[f32]) -> f32 {
    v.iter().map(|x| x * x).sum::<f32>().sqrt()
}

fn dot(a: &[f32], b: &[f32]) -> Result<f32> {
    if a.len() != b.len() {
        return Err(anyhow!("length mismatch: {} vs {}", a.len(), b.len()));
    }
    Ok(a.iter().zip(b.iter()).map(|(x, y)| x * y).sum())
}

fn mean(v: &[f32]) -> f32 {
    if v.is_empty() {
        return 0.0;
    }
    v.iter().sum::<f32>() / (v.len() as f32)
}

fn corr(a: &[f32], b: &[f32]) -> Result<f32> {
    if a.len() != b.len() {
        return Err(anyhow!("length mismatch: {} vs {}", a.len(), b.len()));
    }
    let ma = mean(a);
    let mb = mean(b);
    let mut num = 0.0f32;
    let mut da = 0.0f32;
    let mut db = 0.0f32;
    for (&x, &y) in a.iter().zip(b.iter()) {
        let xa = x - ma;
        let yb = y - mb;
        num += xa * yb;
        da += xa * xa;
        db += yb * yb;
    }
    let den = (da * db).sqrt();
    if den == 0.0 {
        return Err(anyhow!("corr denominator zero"));
    }
    Ok(num / den)
}

pub fn overlap(defn: &str, norm: &str, a: &[f32], b: &[f32]) -> Result<f32> {
    match (defn, norm) {
        ("dot(normalize(a),normalize(b))", "l2") | ("cosine(a,b)", "l2") => {
            let na = l2_norm(a);
            let nb = l2_norm(b);
            if na == 0.0 || nb == 0.0 {
                return Err(anyhow!("zero norm"));
            }
            Ok(dot(a, b)? / (na * nb))
        }
        ("corr(a,b)", "l2") => corr(a, b),
        _ => Err(anyhow!(
            "unsupported overlap_definition/norm: {defn} / {norm}"
        )),
    }
}

/// Compute u_perp = u - proj_u_on_basis, returning new vector.
pub fn gram_schmidt_orthogonalize(mut v: Vec<f32>, basis: &[Vec<f32>]) -> Result<Vec<f32>> {
    for b in basis {
        let bb = dot(b, b)?;
        if bb == 0.0 {
            continue;
        }
        let coeff = dot(&v, b)? / bb;
        for i in 0..v.len() {
            v[i] -= coeff * b[i];
        }
    }
    Ok(v)
}
