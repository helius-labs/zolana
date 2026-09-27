use std::{
    path::{Path, PathBuf},
    process::Command,
};

use ark_bn254::Fr;
use ark_circom::{Wasm, WitnessCalculator};
use num_bigint::BigInt;
use wasmer::{imports, Function, Instance, Memory, MemoryType, Module, RuntimeError, Store};

use super::{artifacts, iden3, locked, path};

pub struct Compiled {
    pub r1cs: PathBuf,
    pub wasm: PathBuf,
}

impl Compiled {
    pub fn read_r1cs(&self) -> iden3::R1cs {
        iden3::read_r1cs(&std::fs::read(&self.r1cs).expect("circom r1cs"))
    }

    pub fn witness(&self, inputs: &[(&str, &str)]) -> Result<Vec<Fr>, String> {
        let mut store = Store::default();
        let mut calculator = calculator(&mut store, &self.wasm);
        let inputs = inputs.iter().map(|(name, decimal)| {
            let value = BigInt::parse_bytes(decimal.as_bytes(), 10).expect("decimal input");
            (name.to_string(), vec![value])
        });
        calculator
            .calculate_witness_element::<Fr, _>(&mut store, inputs, true)
            .map_err(|report| match report.downcast_ref::<RuntimeError>() {
                Some(error) => error.message(),
                None => report.to_string(),
            })
    }
}

// ark-circom's own runtime ignores `exceptionHandler`, so a failed `===`
// would still return a witness; circom's runtime aborts the calculation.
fn calculator(store: &mut Store, wasm: &Path) -> WitnessCalculator {
    let module = Module::from_file(&*store, wasm).expect("circom wasm");
    let memory = Memory::new(store, MemoryType::new(2000, None, false)).expect("wasm memory");
    let imports = imports! {
        "env" => {
            "memory" => memory,
        },
        "runtime" => {
            "error" => Function::new_typed(store, |_: i32, _: i32, _: i32, _: i32, _: i32, _: i32| {
                Err::<(), _>(RuntimeError::new("circom runtime error"))
            }),
            "exceptionHandler" => Function::new_typed(store, |code: i32| {
                Err::<(), _>(RuntimeError::new(exception(code)))
            }),
            "logSetSignal" => Function::new_typed(store, |_: i32, _: i32| {}),
            "logGetSignal" => Function::new_typed(store, |_: i32, _: i32| {}),
            "logFinishComponent" => Function::new_typed(store, |_: i32| {}),
            "logStartComponent" => Function::new_typed(store, |_: i32| {}),
            "log" => Function::new_typed(store, |_: i32| {}),
            "showSharedRWMemory" => Function::new_typed(store, || {}),
            "printErrorMessage" => Function::new_typed(store, || {}),
            "writeBufferMessage" => Function::new_typed(store, || {}),
        }
    };
    let instance = Instance::new(store, &module, &imports).expect("circom instance");
    WitnessCalculator::new_from_wasm(store, Wasm::new(instance)).expect("witness calculator")
}

fn exception(code: i32) -> &'static str {
    match code {
        1 => "Signal not found",
        2 => "Too many signals set",
        3 => "Signal already set",
        4 => "Assert Failed",
        5 => "Not enough memory",
        6 => "Input signal array access exceeds the size",
        _ => "Unknown error",
    }
}

pub fn compile(relative: &str) -> Compiled {
    let relative = Path::new(relative);
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/unit")
        .join(relative);
    let name = relative
        .file_stem()
        .and_then(|stem| stem.to_str())
        .expect("circom file name");
    let dir = artifacts()
        .join("circom")
        .join(relative.parent().expect("circom directory"));
    let compiled = Compiled {
        r1cs: dir.join(format!("{name}.r1cs")),
        wasm: dir.join(format!("{name}_js/{name}.wasm")),
    };
    let _lock = locked(&dir);
    let copy = dir.join(format!("{name}.circom"));
    let bytes = std::fs::read(&source).expect("circom source");
    let current = std::fs::read(&copy).is_ok_and(|compiled_from| compiled_from == bytes);
    if current && compiled.r1cs.exists() && compiled.wasm.exists() {
        return compiled;
    }
    let output = Command::new("circom")
        .args([
            path(&source),
            "--O0",
            "--r1cs",
            "--wasm",
            "--sym",
            "-o",
            path(&dir),
        ])
        .output()
        .expect("circom on PATH");
    assert!(
        output.status.success(),
        "circom {} failed:\n{}\n{}",
        relative.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::write(&copy, bytes).expect("compiled source copy");
    compiled
}
