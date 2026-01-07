use proptest::prelude::*;
use steering_run_verifier::kernel::{
    approx_eq_mat, approx_eq_vec, mat_mul, mat_vec_mul, max_abs_mat, vec_add, Mat, VecF,
};

fn projection_from_mask(mask: u8, n: usize) -> Mat {
    // Diagonal projection P with entries in {0,1}.
    // Guarantees P^2 = P exactly.
    let mut p = vec![vec![0.0_f64; n]; n];
    for i in 0..n {
        let bit = (mask >> i) & 1;
        p[i][i] = bit as f64;
    }
    p
}

fn phi_supported_off_projection(mask: u8, n: usize, entries: [f64; 9]) -> Mat {
    // Build Phi, then enforce:
    // - rows in S are zero  (P*Phi = 0)
    // - cols in S are zero  (Phi*P = 0)
    // where S = { i : P_ii = 1 }.
    //
    // This implies (I-P) Phi (I-P) = Phi exactly for diagonal P.
    let mut phi = vec![vec![0.0_f64; n]; n];
    let mut k = 0usize;
    for i in 0..n {
        for j in 0..n {
            phi[i][j] = entries[k];
            k += 1;
        }
    }

    for i in 0..n {
        let in_s_i = ((mask >> i) & 1) == 1;
        for j in 0..n {
            let in_s_j = ((mask >> j) & 1) == 1;
            if in_s_i || in_s_j {
                phi[i][j] = 0.0;
            }
        }
    }

    phi
}

proptest! {
    // Property: if structural constraints hold (here: diagonal projection P and Phi supported on (I-P)),
    // then invariance holds: P(x + Phi x) = P x.
    #[test]
    fn prop_projection_invariance_under_descent(
        mask in 0u8..8u8, // n=3 => 3 bits
        entries in proptest::array::uniform9(-5.0f64..5.0f64),
        x in proptest::collection::vec(-10.0f64..10.0f64, 3),
    ) {
        let n = 3usize;
        let eps = 1e-12_f64;

        let p = projection_from_mask(mask, n);
        let phi = phi_supported_off_projection(mask, n, entries);

        // Sanity: structural constraints (exact / epsilon-level)
        let p2 = mat_mul(&p, &p);
        prop_assert!(approx_eq_mat(&p2, &p, 0.0));

        let pphi = mat_mul(&p, &phi);
        prop_assert!(max_abs_mat(&pphi) <= eps);

        // Invariance check
        let x: VecF = x;
        let phix = mat_vec_mul(&phi, &x);
        let x2 = vec_add(&x, &phix);

        let px  = mat_vec_mul(&p, &x);
        let px2 = mat_vec_mul(&p, &x2);

        prop_assert!(approx_eq_vec(&px, &px2, eps));
    }
}
