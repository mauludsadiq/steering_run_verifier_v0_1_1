# steering_run_verifier_v0_1_1 (KernelWitness v1.1)

This repo is a **deterministic verifier** for a **KernelWitness v1.1** JSON witness.

It provides a single CLI binary:

- `kernel_witness_verifier`

The verifier checks:

1. **Witness structure** (via the pinned JSON schema in this repo).
2. **CAS artifacts** listed in the witness (SHA-256 of bytes at `--cas-dir/<cid>`).
3. **`cid_run` integrity** (recomputes a canonical hash of the witness after blanking configured fields).
4. **Kernel v1.1 math** (numerical checks with explicit `err_inf` vs `eps`):
   - `P^2 = P` (projection idempotence)
   - `Phi^2 = 0` (nilpotence order-2 law)
   - `P·Phi = 0` and `Phi·P = 0` (compatibility)
5. **Termination certificate** (example uses `nilpotence_k`, reports `||Phi^k||_∞` etc.)

When `verify --print-ok` is used, the binary prints a **full, deterministic JSON verification transcript**
(showing *exactly what “ok” means*), suitable for pinning and diffing.

---

## Repo layout (what matters)

- `src/bin/kernel_witness_verifier.rs`  
  The CLI implementation (includes transcript emission).

- `src/kernel.rs`  
  Kernel math checks / termination checks used by the verifier.

- `schema/kernel_witness_v1_1.schema.json`  
  The pinned JSON schema for KernelWitness v1.1.

- `examples/kernel_witness_example.json`  
  A working example witness (with `projection`, `descent`, `termination`, `artifacts`, `run.cid_run`, etc.)

- `examples/kernel_cas/`  
  Content-addressed files referenced by the example witness (`cid_kw_schema_v1_1`, `cid_kw_verifier_v1_1`, …).

- `runs/verify_transcript.json` (generated)  
  A JSON transcript produced by `verify --print-ok`.  
  Note: `.gitignore` keeps `runs/*` ignored **except** `runs/verify_transcript*.json`.

---

## Requirements

### Required
- Rust toolchain (stable) with Cargo (install via rustup)

### Used by the recommended commands
- `jq`
- SHA-256 tool:
  - macOS: `shasum -a 256`
  - Linux: `sha256sum`

---

## Clone + build (fresh terminal)

```bash
git clone https://github.com/mauludsadiq/steering_run_verifier_v0_1_1.git
cd steering_run_verifier_v0_1_1

cargo build --release
```

Binary path:

```bash
target/release/kernel_witness_verifier
```

---

## Quickstart: verify the included example + store transcript

```bash
mkdir -p runs

target/release/kernel_witness_verifier verify \
  --witness examples/kernel_witness_example.json \
  --cas-dir examples/kernel_cas \
  --print-ok | tee runs/verify_transcript.json
```

Sanity check transcript JSON:

```bash
jq -e . runs/verify_transcript.json >/dev/null
```

Print a compact summary:

```bash
jq -r '.ok, .cid_run_matches, (.laws_v1_1[] | "\(.name)\t ok=\(.ok)\t err_inf=\(.err_inf)\t eps=\(.eps)")' runs/verify_transcript.json
```

Expected: `true`, `true`, then each law `ok=true`.

---

## CLI reference

### 1) Compute `cid_run` for a witness

```bash
target/release/kernel_witness_verifier cid-run \
  --witness examples/kernel_witness_example.json
```

This prints JSON including `.cid_run`.

### 2) Verify a witness

```bash
target/release/kernel_witness_verifier verify \
  --witness examples/kernel_witness_example.json \
  --cas-dir examples/kernel_cas
```

### 3) Verify + emit full transcript JSON

```bash
target/release/kernel_witness_verifier verify \
  --witness examples/kernel_witness_example.json \
  --cas-dir examples/kernel_cas \
  --print-ok
```

---

## Repin flow (when verifier source changes)

If you edit `src/bin/kernel_witness_verifier.rs` (or anything that should be pinned),
you must update:

- the CAS blob `examples/kernel_cas/cid_kw_verifier_v1_1`
- the witness artifact hash for that CID
- the witness `run.cid_run`

Do it in **separate steps** (stable, no half-writes).

### Step A — build

```bash
cargo build --release
mkdir -p runs
```

### Step B — repin current verifier source into CAS + compute hash

macOS:

```bash
cp -f src/bin/kernel_witness_verifier.rs examples/kernel_cas/cid_kw_verifier_v1_1
VERIFIER_HASH="$(shasum -a 256 examples/kernel_cas/cid_kw_verifier_v1_1 | awk '{print $1}')"
echo "$VERIFIER_HASH"
```

Linux:

```bash
cp -f src/bin/kernel_witness_verifier.rs examples/kernel_cas/cid_kw_verifier_v1_1
VERIFIER_HASH="$(sha256sum examples/kernel_cas/cid_kw_verifier_v1_1 | awk '{print $1}')"
echo "$VERIFIER_HASH"
```

### Step C — write the new verifier hash into the witness (atomic write)

```bash
tmp="$(mktemp examples/kernel_witness_example.json.XXXXXX)"
jq -cS --arg vh "$VERIFIER_HASH" '
  .artifacts.items |= (map(
    if .cid=="cid_kw_verifier_v1_1" then .bytes_hash=$vh else . end
  ))
' examples/kernel_witness_example.json > "$tmp"
mv -f "$tmp" examples/kernel_witness_example.json
```

### Step D — recompute `cid_run` and write it back (atomic write)

```bash
CID_RUN="$(target/release/kernel_witness_verifier cid-run --witness examples/kernel_witness_example.json | jq -r '.cid_run')"
tmp="$(mktemp examples/kernel_witness_example.json.XXXXXX)"
jq -cS --arg cr "$CID_RUN" '.run.cid_run = $cr' examples/kernel_witness_example.json > "$tmp"
mv -f "$tmp" examples/kernel_witness_example.json
```

### Step E — verify again and store transcript

```bash
target/release/kernel_witness_verifier verify \
  --witness examples/kernel_witness_example.json \
  --cas-dir examples/kernel_cas \
  --print-ok | tee runs/verify_transcript.json

jq -e . runs/verify_transcript.json >/dev/null
```

---

## Troubleshooting

### `CID_RUN_MISMATCH`
Meaning: recomputed `cid_run` does not match `.run.cid_run`.

Fix: run **Step D** after any witness edit.

### Transcript contains an error JSON
If verification fails, output is an error JSON (still valid JSON) and `tee` writes it.
That’s the pinned failure report.

### Avoid overwriting transcripts
Use a timestamped transcript file:

```bash
ts="$(date +%Y%m%d_%H%M%S)"
target/release/kernel_witness_verifier verify \
  --witness examples/kernel_witness_example.json \
  --cas-dir examples/kernel_cas \
  --print-ok | tee "runs/verify_transcript_${ts}.json"
```

---

## Determinism (operational)
Given the same:
- witness JSON,
- CAS directory contents,
- tolerance `eps`,
the verifier emits the same transcript JSON:
- identical hashes,
- identical computed matrices,
- identical `err_inf` values,
- identical termination metrics.

This makes verification auditable and diffable across commits and machines.
