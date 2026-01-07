use anyhow::{anyhow, Result};

pub type Mat = Vec<Vec<i64>>;
pub type VecI = Vec<i64>;

pub fn mat_dim(m: &Mat) -> Result<usize> {
    if m.is_empty() {
        return Err(anyhow!("matrix is empty"));
    }
    let n = m.len();
    for row in m {
        if row.len() != n {
            return Err(anyhow!("matrix is not square: {}x{}", n, row.len()));
        }
    }
    Ok(n)
}

pub fn vec_dim(v: &VecI, n: usize) -> Result<()> {
    if v.len() != n {
        return Err(anyhow!(
            "vector dim mismatch: expected {}, got {}",
            n,
            v.len()
        ));
    }
    Ok(())
}

pub fn mat_mul(a: &Mat, b: &Mat) -> Result<Mat> {
    let n = mat_dim(a)?;
    let nb = mat_dim(b)?;
    if n != nb {
        return Err(anyhow!("mat_mul dim mismatch: {} vs {}", n, nb));
    }

    let mut out = vec![vec![0i64; n]; n];

    for (i, row_a) in a.iter().enumerate() {
        for (k, &aik) in row_a.iter().enumerate() {
            if aik == 0 {
                continue;
            }
            let row_b = &b[k];
            for (j, &bkj) in row_b.iter().enumerate() {
                out[i][j] = out[i][j].saturating_add(aik.saturating_mul(bkj));
            }
        }
    }

    Ok(out)
}

pub fn mat_add(a: &Mat, b: &Mat, sign_b: i64) -> Result<Mat> {
    let n = mat_dim(a)?;
    let nb = mat_dim(b)?;
    if n != nb {
        return Err(anyhow!("mat_add dim mismatch: {} vs {}", n, nb));
    }
    let mut out = vec![vec![0i64; n]; n];
    for (i, row_a) in a.iter().enumerate() {
        for (j, &aij) in row_a.iter().enumerate() {
            out[i][j] = aij.saturating_add(sign_b.saturating_mul(b[i][j]));
        }
    }
    Ok(out)
}

pub fn mat_eq(a: &Mat, b: &Mat) -> Result<bool> {
    let n = mat_dim(a)?;
    let nb = mat_dim(b)?;
    if n != nb {
        return Ok(false);
    }
    for (i, row_a) in a.iter().enumerate() {
        for (j, &aij) in row_a.iter().enumerate() {
            if aij != b[i][j] {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

pub fn mat_identity(n: usize) -> Mat {
    let mut i = vec![vec![0i64; n]; n];
    for (k, row) in i.iter_mut().enumerate() {
        row[k] = 1;
    }
    i
}

pub fn mat_apply(a: &Mat, x: &VecI) -> Result<VecI> {
    let n = mat_dim(a)?;
    vec_dim(x, n)?;

    let mut out = vec![0i64; n];
    for (i, row_a) in a.iter().enumerate() {
        let acc: i64 = row_a
            .iter()
            .zip(x.iter())
            .map(|(&aij, &xj)| aij.saturating_mul(xj))
            .fold(0i64, |s, t| s.saturating_add(t));
        out[i] = acc;
    }
    Ok(out)
}

pub fn is_zero_vec(x: &VecI) -> bool {
    x.iter().all(|&t| t == 0)
}

pub fn termination_height_under_phi(phi: &Mat, k_max: usize, x0: &VecI) -> Result<usize> {
    if is_zero_vec(x0) {
        return Ok(0);
    }
    let mut cur = x0.clone();
    for k in 1..=k_max {
        cur = mat_apply(phi, &cur)?;
        if is_zero_vec(&cur) {
            return Ok(k);
        }
    }
    Err(anyhow!("did not reach 0 within nilpotence_k={}", k_max))
}

fn phi_power(phi: &Mat, k: usize) -> Result<Mat> {
    let n = mat_dim(phi)?;
    if k == 0 {
        return Ok(mat_identity(n));
    }
    let mut out = phi.clone();
    for _ in 1..k {
        out = mat_mul(&out, phi)?;
    }
    Ok(out)
}

pub fn check_kernel_axioms(p: &Mat, phi: &Mat, nilpotence_k: usize) -> Result<()> {
    let n = mat_dim(p)?;
    let nphi = mat_dim(phi)?;
    if n != nphi {
        return Err(anyhow!("P and Phi dim mismatch: {} vs {}", n, nphi));
    }

    let pp = mat_mul(p, p)?;
    if !mat_eq(&pp, p)? {
        return Err(anyhow!("P is not idempotent: P^2 != P"));
    }

    let pphi = mat_mul(p, phi)?;
    let z = vec![vec![0i64; n]; n];
    if !mat_eq(&pphi, &z)? {
        return Err(anyhow!("compatibility failed: P*Phi != 0"));
    }

    let i = mat_identity(n);
    let ip = mat_add(&i, p, -1)?;
    let lhs = mat_mul(&ip, &mat_mul(phi, &ip)?)?;
    if !mat_eq(&lhs, phi)? {
        return Err(anyhow!("support failed: (I-P)Phi(I-P) != Phi"));
    }

    let phi_k = phi_power(phi, nilpotence_k)?;
    let test = mat_mul(&phi_k, &ip)?;
    if !mat_eq(&test, &z)? {
        return Err(anyhow!(
            "nilpotence failed on residue: Phi^k * (I-P) != 0 for k={}",
            nilpotence_k
        ));
    }

    Ok(())
}
