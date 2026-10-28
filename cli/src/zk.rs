//! `zolana zk` and `zolana build-zk-program` over the circuit crate build of
//! the zk DSL (`spr_program::build`).

use anyhow::{anyhow, Result};
use spr_program::{
    build::{
        self, BuildError, BuildOptions, CompileOptions, ExportVerifierOptions, ImportOptions,
        PackageSelection, SbfOptions, SetupOptions, WasmTarget,
    },
    SetupKind,
};

use crate::args::{
    ZkBuildOptions, ZkCommand, ZkCompileOptions, ZkExportVerifierOptions, ZkImportOptions,
    ZkPackageOptions, ZkSetupKind, ZkSetupOptions, ZkWasmTarget,
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
        ZkCommand::Import(opts) => build::import(&import_options(opts)),
        ZkCommand::ExportVerifier(opts) => build::export_verifier(&export_verifier_options(opts)),
    }
    .map_err(cli_error)
}

/// Names the derives and flags of this CLI in the errors whose library text is
/// generic.
fn cli_error(error: BuildError) -> anyhow::Error {
    match error {
        BuildError::NoCircuits(manifest) => anyhow!(
            "{} derives no ZK circuit: a circuit is a struct with exactly `private` and `public` fields deriving ZkCircuit or ZkProgramCircuit",
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
        nightly: opts.nightly,
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
        r1cs: opts.r1cs,
        out: opts.out,
    }
}

fn import_options(opts: ZkImportOptions) -> ImportOptions {
    ImportOptions {
        package: package(opts.package),
        zkey: opts.zkey,
        r1cs: opts.r1cs,
        out: opts.out,
    }
}

fn export_verifier_options(opts: ZkExportVerifierOptions) -> ExportVerifierOptions {
    ExportVerifierOptions {
        package: package(opts.package),
        checksums: opts.checksums,
        setup: match opts.setup {
            ZkSetupKind::Production => SetupKind::Production,
            ZkSetupKind::SingleParty => SetupKind::SingleParty,
            ZkSetupKind::Test => SetupKind::InsecureTest,
        },
        pk: opts.pk,
        out: opts.out,
    }
}
