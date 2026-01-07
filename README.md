# steering_run_verifier (Rust)

**Purpose:** Verify a `SteeringRunWitness v0.1.1` witness JSON as an **audit-grade, checkable artifact**.

This verifier is intentionally strict and implements:

- JSON Schema validation (draft 2020-12)
- `cid_run` recomputation via canonical JSON + dotpath blanking
- Normative rule: `CID_REFERENCE_CLOSURE_V0_1_1` (closure + lexical validity)
- Artifact byte-hash checks (`sha256`)
- Direction tensor hash consistency and **orthogonalization overlap checks**
- `metrics.verification_mode` policy (hash-only supported; rerun mode gated)

## Project layout

- `schema/steering_run_witness_v0_1_1.schema.json` — pinned schema
- `src/` — Rust CLI + verifier logic

## CAS convention

This repo uses a minimal CAS convention:

- For any `cid` string, bytes are expected at:

```
<cas_dir>/<cid>
```

No CID scheme is assumed; only the pinned lexical predicate is enforced:

```
^[A-Za-z0-9._:-]{8,}$
```

## Build

```bash
cargo build --release
```

## Run

```bash
cargo run --release -- verify \
  --witness path/to/witness.json \
  --cas-dir path/to/cas \
  --print-ok
```

### Schema override (optional)

```bash
cargo run --release -- verify \
  --witness witness.json \
  --cas-dir cas \
  --schema ./schema/steering_run_witness_v0_1_1.schema.json
```

## Output

- On success: prints a JSON success object (if `--print-ok`) and exits `0`.
- On failure: prints a deterministic JSON error and exits `1`.

## Verification-mode policy

- If `metrics.verification_mode == "hash_only"`: supported.
- If `metrics.verification_mode == "rerun_required"`: this verifier **rejects** unless `--allow-rerun-mode` is passed.
  Even with `--allow-rerun-mode`, this build still performs **hash-only checks** (it does not execute the model).
