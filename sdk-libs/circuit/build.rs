use ark_ff::PrimeField;
use light_poseidon::parameters::bn254_x5::get_poseidon_parameters;
use std::{env, fmt::Write, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let mut out = String::new();
    let mut arms = String::new();
    for inputs in 1..=12 {
        let p = get_poseidon_parameters::<ark_bn254::Fr>((inputs + 1) as u8)
            .expect("protocol Poseidon parameters");
        write!(out, "const ARK_{inputs}: &[Field] = &[").unwrap();
        for value in p.ark {
            write!(out, "Field::constant(\"{}\"),", value.into_bigint()).unwrap();
        }
        write!(out, "];\nconst MDS_{inputs}: &[Field] = &[").unwrap();
        for row in p.mds {
            for value in row {
                write!(out, "Field::constant(\"{}\"),", value.into_bigint()).unwrap();
            }
        }
        out.push_str("];\n");
        writeln!(arms, "{inputs} => Parameters {{ width: {}, full: {}, partial: {}, ark: ARK_{inputs}, mds: MDS_{inputs} }},",
            p.width, p.full_rounds, p.partial_rounds).unwrap();
    }
    write!(out, "fn parameters(inputs: usize) -> Parameters {{ match inputs {{\n{arms}_ => panic!(\"Poseidon accepts 1 to 12 inputs\"), }} }}\n").unwrap();
    fs::write(PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("poseidon.rs"), out)
        .expect("write Poseidon constants");
}
