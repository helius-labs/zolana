//! Circuit build and key management for the Zolana CLI.

mod build;

use anyhow::{anyhow, Result};
use build::{
    BuildError, BuildOptions, CompileOptions, ExportVerifierOptions, PackageSelection, SbfOptions,
    SetupOptions, WasmTarget,
};

use crate::args::{
    ZkBuildOptions, ZkCommand, ZkCompileOptions, ZkExportVerifierOptions, ZkPackageOptions,
    ZkSetupOptions, ZkWasmTarget,
};

pub(crate) fn run_build_zk_program(opts: ZkBuildOptions) -> Result<()> {
    build::build(&BuildOptions {
        compile: compile_options(opts.compile),
        sbf: SbfOptions {
            skip_sbf: opts.skip_sbf,
            sbf_features: opts.sbf_features,
            sbf_out_dir: opts.sbf_out_dir,
        },
    })
    .map_err(cli_error)
}

pub(crate) fn run_zk(command: ZkCommand) -> Result<()> {
    match command {
        ZkCommand::Compile(opts) => build::compile(&compile_options(opts)),
        ZkCommand::Setup(opts) => build::setup(&setup_options(opts)),
        ZkCommand::ExportVerifier(opts) => build::export_verifier(&export_verifier_options(opts)),
    }
    .map_err(cli_error)
}

/// Names the derives and flags of this CLI in the errors whose library text is
/// generic.
fn cli_error(error: BuildError) -> anyhow::Error {
    match error {
        BuildError::NoCircuits(manifest) => anyhow!(
            "{} derives no ZK program: declare `private` and `public` fields and derive ZkProgram",
            manifest.display()
        ),
        BuildError::NothingToCompile => {
            anyhow!("--skip-r1cs, --skip-keys and --skip-wasm leave nothing to compile")
        }
        error => error.into(),
    }
}

fn package(opts: ZkPackageOptions) -> PackageSelection {
    PackageSelection {
        package: opts.package,
        manifest_path: opts.manifest_path,
    }
}

fn compile_options(opts: ZkCompileOptions) -> CompileOptions {
    CompileOptions {
        package: package(opts.package),
        test: opts.test,
        skip_r1cs: opts.skip_r1cs,
        skip_keys: opts.skip_keys,
        skip_wasm: opts.skip_wasm,
        check: opts.check,
        r1cs_features: opts.r1cs_features,
        r1cs_out: opts.r1cs_out,
        wasm_features: opts.wasm_features,
        wasm_target: match opts.wasm_target {
            ZkWasmTarget::Web => WasmTarget::Web,
            ZkWasmTarget::Nodejs => WasmTarget::Nodejs,
        },
        single_threaded: opts.single_threaded,
        no_prover: opts.no_prover,
        verifier: opts.verifier,
        wasm_opt: opts.wasm_opt,
        wasm_out: opts.wasm_out,
    }
}

fn setup_options(opts: ZkSetupOptions) -> SetupOptions {
    SetupOptions {
        package: package(opts.package),
        test: opts.test,
        out: opts.out,
    }
}

fn export_verifier_options(opts: ZkExportVerifierOptions) -> ExportVerifierOptions {
    ExportVerifierOptions {
        package: package(opts.package),
        checksums: opts.checksums,
        out: opts.out,
    }
}
