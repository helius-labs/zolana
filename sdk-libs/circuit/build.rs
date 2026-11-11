use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, Field, PrimeField};
use light_poseidon::parameters::bn254_x5::get_poseidon_parameters;
use std::{env, fmt::Write, fs, path::PathBuf};

// Derive the optimized schedule from Light's parameters at build time, following
// https://github.com/iden3/circomlibjs/blob/main/tools/poseidon_optimize_constants.js
type Matrix = Vec<Vec<Fr>>;

fn inverse(matrix: &Matrix) -> Matrix {
    let n = matrix.len();
    // Each row is the matrix row followed by the matching identity row.
    let mut rows: Matrix = matrix
        .iter()
        .enumerate()
        .map(|(i, row)| {
            let identity = (0..n).map(|j| if i == j { Fr::ONE } else { Fr::ZERO });
            row.iter().copied().chain(identity).collect()
        })
        .collect();
    for column in 0..n {
        let entry = |row: &Vec<Fr>| *row.get(column).expect("square Poseidon matrix");
        let pivot = column
            + rows
                .iter()
                .skip(column)
                .position(|row| entry(row) != Fr::ZERO)
                .expect("invertible Poseidon matrix");
        rows.swap(column, pivot);
        let pivot_row = {
            let row = rows.get_mut(column).expect("pivot row");
            let scale = entry(row).inverse().expect("nonzero pivot");
            for value in row.iter_mut() {
                *value *= scale;
            }
            row.clone()
        };
        for (i, row) in rows.iter_mut().enumerate() {
            if i != column {
                let scale = entry(row);
                for (value, pivot) in row.iter_mut().zip(&pivot_row) {
                    *value -= scale * pivot;
                }
            }
        }
    }
    rows.into_iter()
        .map(|row| row.into_iter().skip(n).collect())
        .collect()
}

fn vector_matrix(vector: &[Fr], matrix: &Matrix) -> Vec<Fr> {
    (0..vector.len())
        .map(|j| {
            vector
                .iter()
                .zip(matrix)
                .map(|(value, row)| *value * row.get(j).expect("square Poseidon matrix"))
                .sum()
        })
        .collect()
}

fn multiply(a: &Matrix, b: &Matrix) -> Matrix {
    a.iter().map(|row| vector_matrix(row, b)).collect()
}

// Circomlib's Supplement B schedule: move constants through M^-1 so each
// partial round adds just one constant, after its S-box.
fn compress_constants(ark: &[Fr], matrix: &Matrix, full: usize, partial: usize) -> Vec<Fr> {
    let t = matrix.len();
    let half = full / 2;
    let inv = inverse(matrix);
    let rounds: Vec<&[Fr]> = ark.chunks(t).collect();
    let round_constants = |round: usize| *rounds.get(round).expect("a constant row per round");
    let mut constants = round_constants(0).to_vec();
    for round in 1..half {
        constants.extend(vector_matrix(round_constants(round), &inv));
    }
    let mut accumulated = round_constants(half + partial).to_vec();
    let mut partial_constants = Vec::with_capacity(partial);
    for round in (half..half + partial).rev() {
        let mut moved = vector_matrix(&accumulated, &inv);
        let first = moved.first_mut().expect("a nonempty Poseidon state");
        partial_constants.push(*first);
        *first = Fr::ZERO;
        accumulated = moved
            .iter()
            .zip(round_constants(round))
            .map(|(moved, constant)| *moved + constant)
            .collect();
    }
    constants.extend(vector_matrix(&accumulated, &inv));
    constants.extend(partial_constants.into_iter().rev());
    for round in half + partial + 1..full + partial {
        constants.extend(vector_matrix(round_constants(round), &inv));
    }
    assert_eq!(constants.len(), full * t + partial);
    constants
}

// Factor m = block * sparse, where block leaves lane zero alone and sparse
// has an identity lower-right block. Block commutes with the partial S-box.
fn factor_sparse(matrix: &Matrix) -> (Matrix, Vec<Fr>) {
    let (first_row, lower_rows) = matrix.split_first().expect("a nonempty Poseidon matrix");
    let (corner, top) = first_row.split_first().expect("a nonempty Poseidon row");
    let lower: Matrix = lower_rows
        .iter()
        .map(|row| row.iter().skip(1).copied().collect())
        .collect();
    let inv = inverse(&lower);
    let column: Vec<_> = lower_rows
        .iter()
        .map(|row| *row.first().expect("a nonempty Poseidon row"))
        .collect();
    let mut sparse = vec![*corner];
    sparse.extend(
        inv.iter()
            .map(|row| row.iter().zip(&column).map(|(a, b)| *a * b).sum::<Fr>()),
    );
    sparse.extend_from_slice(top);
    // The matrix with its first row and column replaced by the identity's.
    let block = matrix
        .iter()
        .enumerate()
        .map(|(i, row)| {
            row.iter()
                .enumerate()
                .map(|(j, value)| match (i, j) {
                    (0, 0) => Fr::ONE,
                    (0, _) | (_, 0) => Fr::ZERO,
                    _ => *value,
                })
                .collect()
        })
        .collect();
    (block, sparse)
}

fn sparse_matrices(matrix: &Matrix, partial: usize) -> (Matrix, Vec<Fr>) {
    let mut accumulated = matrix.clone();
    let mut rounds = Vec::with_capacity(partial);
    for _ in 0..partial {
        let (block, sparse) = factor_sparse(&accumulated);
        rounds.push(sparse);
        accumulated = multiply(matrix, &block);
    }
    (accumulated, rounds.into_iter().rev().flatten().collect())
}

fn emit(out: &mut String, name: &str, values: impl IntoIterator<Item = Fr>) {
    write!(out, "const {name}: &[Field] = &[").unwrap();
    for value in values {
        write!(out, "Field::constant(\"{}\"),", value.into_bigint()).unwrap();
    }
    out.push_str("];\n");
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let mut out = String::new();
    let mut arms = String::new();
    for inputs in 1..=12 {
        let p = get_poseidon_parameters::<Fr>((inputs + 1) as u8)
            .expect("protocol Poseidon parameters");
        // Light uses matrix * column; the optimized circomlib schedule uses
        // row * matrix. Transpose before transforming constants and matrices.
        let matrix: Matrix = (0..p.width)
            .map(|i| {
                p.mds
                    .iter()
                    .map(|row| *row.get(i).expect("square Poseidon matrix"))
                    .collect()
            })
            .collect();
        let constants = compress_constants(&p.ark, &matrix, p.full_rounds, p.partial_rounds);
        let (pre_sparse, sparse) = sparse_matrices(&matrix, p.partial_rounds);
        emit(&mut out, &format!("ARK_{inputs}"), constants);
        emit(
            &mut out,
            &format!("MDS_{inputs}"),
            matrix.into_iter().flatten(),
        );
        emit(
            &mut out,
            &format!("PRE_SPARSE_{inputs}"),
            pre_sparse.into_iter().flatten(),
        );
        emit(&mut out, &format!("SPARSE_{inputs}"), sparse);
        writeln!(arms, "{inputs} => Some(Parameters {{ width: {}, full: {}, partial: {}, ark: ARK_{inputs}, mds: MDS_{inputs}, pre_sparse: PRE_SPARSE_{inputs}, sparse: SPARSE_{inputs} }}),",
            p.width, p.full_rounds, p.partial_rounds).unwrap();
    }
    write!(out, "fn parameters(inputs: usize) -> Option<Parameters> {{ match inputs {{\n{arms}_ => None, }} }}\n").unwrap();
    fs::write(
        PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("poseidon.rs"),
        out,
    )
    .expect("write Poseidon constants");
}
