#![cfg(feature = "external-tools")]

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
    pub sym: PathBuf,
    pub wasm: PathBuf,
}

/// What the witness calculation does when a `===` or `assert` fails.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Asserts {
    /// Abort, as circom's own runtime does.
    Abort,
    /// Continue and return the witness, so the R1CS rows can be checked
    /// against it independently of the calculation.
    Ignore,
}

impl Compiled {
    pub fn read_r1cs(&self) -> iden3::R1cs {
        iden3::read_r1cs(&std::fs::read(&self.r1cs).expect("circom r1cs"))
    }

    /// The R1CS wire of a signal by its full `.sym` name, such as
    /// `main.claimed` or `main.isZero.inv`.
    pub fn wire(&self, signal: &str) -> usize {
        let sym = std::fs::read_to_string(&self.sym).expect("circom sym");
        sym.lines()
            .find_map(|line| {
                let mut fields = line.split(',');
                let wire = fields.nth(1)?;
                (fields.nth(1)? == signal).then(|| wire.parse().expect("sym wire"))
            })
            .unwrap_or_else(|| panic!("no wire for {signal} in {}", self.sym.display()))
    }

    pub fn witness(&self, inputs: &[(&str, &str)]) -> Result<Vec<Fr>, String> {
        let signals: Vec<_> = inputs
            .iter()
            .map(|(name, decimal)| (*name, vec![decimal.to_string()]))
            .collect();
        self.calculate(&signals, Asserts::Abort)
    }

    /// Each input signal is a name with its decimal values: one for a scalar,
    /// the flattened elements for an array.
    pub fn calculate(
        &self,
        inputs: &[(&str, Vec<String>)],
        asserts: Asserts,
    ) -> Result<Vec<Fr>, String> {
        let mut store = Store::default();
        let mut calculator = calculator(&mut store, &self.wasm, asserts);
        let inputs = inputs.iter().map(|(name, decimals)| {
            let values = decimals
                .iter()
                .map(|decimal| BigInt::parse_bytes(decimal.as_bytes(), 10).expect("decimal input"))
                .collect();
            (name.to_string(), values)
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
fn calculator(store: &mut Store, wasm: &Path, asserts: Asserts) -> WitnessCalculator {
    let module = Module::from_file(&*store, wasm).expect("circom wasm");
    let memory = Memory::new(store, MemoryType::new(2000, None, false)).expect("wasm memory");
    let exception_handler = match asserts {
        Asserts::Abort => Function::new_typed(store, |code: i32| {
            Err::<(), _>(RuntimeError::new(exception(code)))
        }),
        Asserts::Ignore => Function::new_typed(store, |_: i32| {}),
    };
    let imports = imports! {
        "env" => {
            "memory" => memory,
        },
        "runtime" => {
            "error" => Function::new_typed(store, |_: i32, _: i32, _: i32, _: i32, _: i32, _: i32| {
                Err::<(), _>(RuntimeError::new("circom runtime error"))
            }),
            "exceptionHandler" => exception_handler,
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
    compile_with(relative, &[])
}

/// Compiles `tests/unit/<relative>` with `--O0`, each of `includes` passed as
/// `-l`. The output is cached per source file and recompiled whenever the
/// source or the include set changes; files reached through an include are
/// not part of the key.
pub fn compile_with(relative: &str, includes: &[PathBuf]) -> Compiled {
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
        sym: dir.join(format!("{name}.sym")),
        wasm: dir.join(format!("{name}_js/{name}.wasm")),
    };
    let _lock = locked(&dir);
    let copy = dir.join(format!("{name}.circom"));
    let include_key = dir.join(format!("{name}.includes"));
    let bytes = std::fs::read(&source).expect("circom source");
    let include_list: String = includes
        .iter()
        .map(|include| format!("{}\n", path(include)))
        .collect();
    let current = std::fs::read(&copy).is_ok_and(|compiled_from| compiled_from == bytes)
        && std::fs::read_to_string(&include_key)
            .is_ok_and(|compiled_with| compiled_with == include_list);
    if current && compiled.r1cs.exists() && compiled.sym.exists() && compiled.wasm.exists() {
        return compiled;
    }
    let output = Command::new("circom")
        .arg(path(&source))
        .args(includes.iter().flat_map(|include| ["-l", path(include)]))
        .args(["--O0", "--r1cs", "--wasm", "--sym", "-o", path(&dir)])
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
    std::fs::write(&include_key, include_list).expect("compiled include list");
    compiled
}
