use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, Field, PrimeField};
use light_poseidon::parameters::bn254_x5::get_poseidon_parameters;
use std::{env, fmt::Write, fs, path::PathBuf};

// Derive the optimized schedule from Light's parameters at build time, following
// https://github.com/iden3/circomlibjs/blob/main/tools/poseidon_optimize_constants.js
type Matrix = Vec<Vec<Fr>>;

fn inverse(matrix: &Matrix) -> Matrix {
    let n = matrix.len();
    let mut rows = vec![vec![Fr::ZERO; 2 * n]; n];
    for i in 0..n {
        rows[i][..n].copy_from_slice(&matrix[i]);
        rows[i][n + i] = Fr::ONE;
    }
    for column in 0..n {
        let pivot = (column..n)
            .find(|&row| rows[row][column] != Fr::ZERO)
            .expect("invertible Poseidon matrix");
        rows.swap(column, pivot);
        let scale = rows[column][column].inverse().unwrap();
        for value in &mut rows[column] {
            *value *= scale;
        }
        let pivot_row = rows[column].clone();
        for (i, row) in rows.iter_mut().enumerate() {
            if i != column {
                let scale = row[column];
                for (value, pivot) in row.iter_mut().zip(&pivot_row) {
                    *value -= scale * pivot;
                }
            }
        }
    }
    rows.into_iter().map(|row| row[n..].to_vec()).collect()
}

fn vector_matrix(vector: &[Fr], matrix: &Matrix) -> Vec<Fr> {
    (0..vector.len())
        .map(|j| {
            vector
                .iter()
                .enumerate()
                .map(|(i, value)| *value * matrix[i][j])
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
    let mut constants = ark[..t].to_vec();
    for round in 1..half {
        constants.extend(vector_matrix(&ark[round * t..(round + 1) * t], &inv));
    }
    let mut accumulated = ark[(half + partial) * t..(half + partial + 1) * t].to_vec();
    let mut partial_constants = Vec::with_capacity(partial);
    for round in (half..half + partial).rev() {
        let mut moved = vector_matrix(&accumulated, &inv);
        partial_constants.push(moved[0]);
        moved[0] = Fr::ZERO;
        for i in 0..t {
            accumulated[i] = moved[i] + ark[round * t + i];
        }
    }
    constants.extend(vector_matrix(&accumulated, &inv));
    constants.extend(partial_constants.into_iter().rev());
    for round in half + partial + 1..full + partial {
        constants.extend(vector_matrix(&ark[round * t..(round + 1) * t], &inv));
    }
    assert_eq!(constants.len(), full * t + partial);
    constants
}

// Factor m = block * sparse, where block leaves lane zero alone and sparse
// has an identity lower-right block. Block commutes with the partial S-box.
fn factor_sparse(matrix: &Matrix) -> (Matrix, Vec<Fr>) {
    let t = matrix.len();
    let lower: Matrix = matrix[1..].iter().map(|row| row[1..].to_vec()).collect();
    let inv = inverse(&lower);
    let column: Vec<_> = matrix[1..].iter().map(|row| row[0]).collect();
    let mut sparse = vec![matrix[0][0]];
    sparse.extend(
        inv.iter()
            .map(|row| row.iter().zip(&column).map(|(a, b)| *a * b).sum::<Fr>()),
    );
    sparse.extend_from_slice(&matrix[0][1..]);
    let mut block = vec![vec![Fr::ZERO; t]; t];
    block[0][0] = Fr::ONE;
    for i in 1..t {
        block[i][1..].copy_from_slice(&matrix[i][1..]);
    }
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
            .map(|i| (0..p.width).map(|j| p.mds[j][i]).collect())
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
        writeln!(arms, "{inputs} => Parameters {{ width: {}, full: {}, partial: {}, ark: ARK_{inputs}, mds: MDS_{inputs}, pre_sparse: PRE_SPARSE_{inputs}, sparse: SPARSE_{inputs} }},",
            p.width, p.full_rounds, p.partial_rounds).unwrap();
    }
    write!(out, "fn parameters(inputs: usize) -> Parameters {{ match inputs {{\n{arms}_ => panic!(\"Poseidon accepts 1 to 12 inputs\"), }} }}\n").unwrap();
    fs::write(
        PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("poseidon.rs"),
        out,
    )
    .expect("write Poseidon constants");
}
