use std::cmp::max;

pub type VecF = Vec<f64>;
pub type Mat = Vec<Vec<f64>>;

pub fn eye(n: usize) -> Mat {
    let mut m = vec![vec![0.0_f64; n]; n];
    for (i, row) in m.iter_mut().enumerate() {
        row[i] = 1.0;
    }
    m
}

pub fn mat_mul(a: &Mat, b: &Mat) -> Mat {
    let n = a.len();
    let m = b[0].len();
    let _k = b.len();

    let mut out = vec![vec![0.0_f64; m]; n];

    for (i, row) in a.iter().enumerate() {
        for (kk, a_ik) in row.iter().enumerate() {
            if *a_ik == 0.0 {
                continue;
            }
            for (j, b_kj) in b[kk].iter().enumerate() {
                out[i][j] += a_ik * b_kj;
            }
        }
    }

    out
}

pub fn mat_vec_mul(a: &Mat, x: &VecF) -> VecF {
    let mut out = vec![0.0_f64; a.len()];
    for (i, row) in a.iter().enumerate() {
        let mut acc = 0.0_f64;
        for (a_ij, x_j) in row.iter().zip(x.iter()) {
            acc += a_ij * x_j;
        }
        out[i] = acc;
    }
    out
}

pub fn vec_add(a: &VecF, b: &VecF) -> VecF {
    a.iter().zip(b.iter()).map(|(x, y)| x + y).collect()
}

pub fn mat_sub(a: &Mat, b: &Mat) -> Mat {
    a.iter()
        .zip(b.iter())
        .map(|(ra, rb)| ra.iter().zip(rb.iter()).map(|(x, y)| x - y).collect())
        .collect()
}

pub fn max_abs_mat(a: &Mat) -> f64 {
    a.iter()
        .flat_map(|r| r.iter())
        .fold(0.0_f64, |acc, v| acc.max(v.abs()))
}

pub fn max_abs_vec(x: &VecF) -> f64 {
    x.iter().fold(0.0_f64, |acc, v| acc.max(v.abs()))
}

pub fn approx_eq_mat(a: &Mat, b: &Mat, eps: f64) -> bool {
    max_abs_mat(&mat_sub(a, b)) <= eps
}

pub fn approx_eq_vec(a: &VecF, b: &VecF, eps: f64) -> bool {
    let mut mx = 0.0_f64;
    for (x, y) in a.iter().zip(b.iter()) {
        mx = mx.max((x - y).abs());
    }
    mx <= eps
}

pub fn pow_mat(a: &Mat, mut e: u64) -> Mat {
    let n = a.len();
    let mut base = a.clone();
    let mut acc = eye(n);

    while e > 0 {
        if (e & 1) == 1 {
            acc = mat_mul(&acc, &base);
        }
        e >>= 1;
        if e > 0 {
            base = mat_mul(&base, &base);
        }
    }

    acc
}

pub fn check_square(m: &Mat, n: usize) -> Result<(), String> {
    if m.len() != n {
        return Err(format!(
            "matrix row count mismatch: got {} expected {}",
            m.len(),
            n
        ));
    }
    for (i, row) in m.iter().enumerate() {
        if row.len() != n {
            return Err(format!(
                "matrix col count mismatch at row {}: got {} expected {}",
                i,
                row.len(),
                n
            ));
        }
    }
    Ok(())
}

pub fn check_vec(x: &VecF, n: usize) -> Result<(), String> {
    if x.len() != n {
        return Err(format!(
            "vector length mismatch: got {} expected {}",
            x.len(),
            n
        ));
    }
    Ok(())
}

pub fn laws_check_all_v1_1(p: &Mat, phi: &Mat, x_samples: &[VecF], eps: f64) -> Result<(), String> {
    let n = p.len();

    check_square(p, n)?;
    check_square(phi, n)?;

    for x in x_samples {
        check_vec(x, n)?;
    }

    let p2 = mat_mul(p, p);
    if !approx_eq_mat(&p2, p, eps) {
        let d = max_abs_mat(&mat_sub(&p2, p));
        return Err(format!("LAW_FAIL_P_IDEMPOTENT max_abs(P^2-P)={}", d));
    }

    let pphi = mat_mul(p, phi);
    if max_abs_mat(&pphi) > eps {
        return Err(format!(
            "LAW_FAIL_P_PHI_ZERO max_abs(P*Phi)={}",
            max_abs_mat(&pphi)
        ));
    }

    let ip = {
        let i = eye(n);
        mat_sub(&i, p)
    };

    let support = mat_mul(&mat_mul(&ip, phi), &ip);
    if !approx_eq_mat(&support, phi, eps) {
        let d = max_abs_mat(&mat_sub(&support, phi));
        return Err(format!("LAW_FAIL_SUPPORT max_abs((I-P)Phi(I-P)-Phi)={}", d));
    }

    for (idx, x) in x_samples.iter().enumerate() {
        let px = mat_vec_mul(p, x);
        let phix = mat_vec_mul(phi, x);
        let x2 = vec_add(x, &phix);
        let px2 = mat_vec_mul(p, &x2);
        if !approx_eq_vec(&px, &px2, eps) {
            let mut mx = 0.0_f64;
            for (a, b) in px.iter().zip(px2.iter()) {
                mx = mx.max((a - b).abs());
            }
            return Err(format!(
                "LAW_FAIL_P_INVARIANCE sample={} max_abs(Px-P(x+Phi x))={}",
                idx, mx
            ));
        }
    }

    Ok(())
}

pub fn check_nilpotence(phi: &Mat, k: u64, eps: f64) -> Result<(), String> {
    let p = pow_mat(phi, k);
    let m = max_abs_mat(&p);
    if m > eps {
        return Err(format!("TERM_FAIL_NILPOTENCE max_abs(Phi^k)={} k={}", m, k));
    }
    Ok(())
}

pub fn check_trace(
    phi: &Mat,
    x_trace: &[VecF],
    h_trace: Option<&[u64]>,
    eps: f64,
) -> Result<(), String> {
    let n = phi.len();

    if x_trace.is_empty() {
        return Err("TERM_FAIL_TRACE_EMPTY".to_string());
    }

    for x in x_trace {
        check_vec(x, n)?;
    }

    for t in 0..(x_trace.len() - 1) {
        let pred = mat_vec_mul(phi, &x_trace[t]);
        if !approx_eq_vec(&pred, &x_trace[t + 1], eps) {
            return Err(format!("TERM_FAIL_TRACE_STEP t={}", t));
        }
    }

    let last = x_trace.last().expect("nonempty");
    if max_abs_vec(last) > eps {
        return Err(format!(
            "TERM_FAIL_TRACE_NOT_ZERO max_abs(last)={}",
            max_abs_vec(last)
        ));
    }

    if let Some(hs) = h_trace {
        if hs.len() != x_trace.len() {
            return Err(format!(
                "TERM_FAIL_H_TRACE_LEN got {} expected {}",
                hs.len(),
                x_trace.len()
            ));
        }
        for t in 0..(hs.len() - 1) {
            if hs[t + 1] >= hs[t] {
                return Err(format!(
                    "TERM_FAIL_H_NOT_DECREASING t={} h_t={} h_next={}",
                    t,
                    hs[t],
                    hs[t + 1]
                ));
            }
        }
        if *hs.last().unwrap_or(&max(1, 1)) != 0 {
            return Err("TERM_FAIL_H_LAST_NOT_ZERO".to_string());
        }
    }

    Ok(())
}
