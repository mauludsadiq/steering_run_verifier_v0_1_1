use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "steering_run_verifier")]
#[command(about = "SteeringRunWitness v0.1.1 verifier (Rust)", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Verify a SteeringRunWitness JSON against schema + normative rules + artifact hashes
    Verify {
        /// Path to witness JSON
        #[arg(long)]
        witness: PathBuf,

        /// CAS directory: bytes are expected at <cas_dir>/<cid>
        #[arg(long)]
        cas_dir: PathBuf,

        /// Optional JSON Schema path (defaults to built-in v0.1.1 schema)
        #[arg(long)]
        schema: Option<PathBuf>,

        /// Allow witnesses with metrics.verification_mode == "rerun_required" to pass structural checks.
        /// Normatively, rerun_required MUST be rerun; this flag only suppresses hard failure.
        #[arg(long)]
        allow_rerun_mode: bool,

        /// Print the OK payload (JSON) on success
        #[arg(long)]
        print_ok: bool,
    },

    /// Compute the normative cid_run for a witness (blanking run.cid_run to "")
    Cid {
        /// Path to witness JSON
        #[arg(long)]
        witness: PathBuf,

        /// Print JSON { "cid_run": "<hex>" } instead of raw hex
        #[arg(long)]
        json: bool,

        /// If set, rewrite the witness file in-place with computed run.cid_run
        #[arg(long)]
        write: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Verify {
            witness,
            cas_dir,
            schema,
            allow_rerun_mode,
            print_ok,
        } => {
            let out = steering_run_verifier::verify::verify_path(
                &witness,
                &cas_dir,
                schema.as_deref(),
                allow_rerun_mode,
            )?;
            if print_ok || !out.ok {
                println!("{}", serde_json::to_string_pretty(&out)?);
            }
            Ok(())
        }

        Commands::Cid {
            witness,
            json,
            write,
        } => {
            let cid = steering_run_verifier::verify::compute_cid_run_for_path(&witness)?;
            if write {
                steering_run_verifier::verify::write_cid_run_in_place(&witness, &cid)?;
            }
            if json {
                println!("{}", serde_json::json!({ "cid_run": cid }));
            } else {
                println!("{cid}");
            }
            Ok(())
        }
    }
}
