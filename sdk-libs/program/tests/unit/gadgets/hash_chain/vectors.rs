use zolana_program::circuit::Field;

use crate::{
    gadgets::reference,
    harness::{
        field::{field, MODULUS_MINUS_1},
        fixture::Named,
    },
};

pub const CHAIN_1_2: &str =
    "7853200120776062878684798364095072458815029376092732009249414926327459813530";
pub const CHAIN_2_1: &str =
    "9708419728795563670286566418307042748092204899363634976546883453490873071450";
pub const POSEIDON_0_0: &str =
    "14744269619966411208579211824598458697587494354926760081771325075741142829156";
pub const POSEIDON_0_1: &str =
    "12583541437132735734108669866114103169564651237895298778035846191048104863326";
pub const FOLD_FROM_ZERO_1_2: &str =
    "11790059851550142146278072775670916642282838830554510149311470233718605478544";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vector {
    pub name: &'static str,
    pub values: &'static [&'static str],
    pub chain: &'static str,
}

impl Named for Vector {
    fn name(&self) -> &'static str {
        self.name
    }
}

impl Vector {
    pub fn values(&self) -> Vec<Field> {
        self.values.iter().map(|value| field(value)).collect()
    }

    pub fn chain(&self) -> Field {
        field(self.chain)
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }
}

pub const VALID: [Vector; 15] = [
    Vector {
        name: "the empty chain is 0",
        values: &[],
        chain: "0",
    },
    Vector {
        name: "[0] chains to 0",
        values: &["0"],
        chain: "0",
    },
    Vector {
        name: "[0, 0, 0] chains to 0",
        values: &["0", "0", "0"],
        chain: "0",
    },
    Vector {
        name: "[0, 0, 0, 0] chains to 0",
        values: &["0", "0", "0", "0"],
        chain: "0",
    },
    Vector {
        name: "[1] chains to 1",
        values: &["1"],
        chain: "1",
    },
    Vector {
        name: "[0, 1] chains as [1]",
        values: &["0", "1"],
        chain: "1",
    },
    Vector {
        name: "[1, 0] chains as [1]",
        values: &["1", "0"],
        chain: "1",
    },
    Vector {
        name: "[1, 2] chains to Poseidon(1, 2)",
        values: &["1", "2"],
        chain: CHAIN_1_2,
    },
    Vector {
        name: "[2, 1] chains to Poseidon(2, 1)",
        values: &["2", "1"],
        chain: CHAIN_2_1,
    },
    Vector {
        name: "[1, 0, 2] chains as [1, 2]",
        values: &["1", "0", "2"],
        chain: CHAIN_1_2,
    },
    Vector {
        name: "[0, 1, 0, 2] chains as [1, 2]",
        values: &["0", "1", "0", "2"],
        chain: CHAIN_1_2,
    },
    Vector {
        name: "[1, 2, 3]",
        values: &["1", "2", "3"],
        chain: "13816780880028945690020260331303642730075999758909899334839547418969502592169",
    },
    Vector {
        name: "[5, 0, 7]",
        values: &["5", "0", "7"],
        chain: "21007229687521157814825902919006068496120320911167801732994749038798743998593",
    },
    Vector {
        name: "[p - 1] chains to p - 1",
        values: &[MODULUS_MINUS_1],
        chain: MODULUS_MINUS_1,
    },
    Vector {
        name: "[1, 2, 3, 4]",
        values: &["1", "2", "3", "4"],
        chain: "11513292746329852516326840859386889450785527380888700527152707126542607443402",
    },
];

pub const INVALID: [Vector; 8] = [
    Vector {
        name: "[1] claimed 0",
        values: &["1"],
        chain: "0",
    },
    Vector {
        name: "[1] claimed Poseidon(0, 1), the fold from zero",
        values: &["1"],
        chain: POSEIDON_0_1,
    },
    Vector {
        name: "[0] claimed Poseidon(0, 0)",
        values: &["0"],
        chain: POSEIDON_0_0,
    },
    Vector {
        name: "[] claimed 1",
        values: &[],
        chain: "1",
    },
    Vector {
        name: "[1, 2] claimed the chain of [2, 1]",
        values: &["1", "2"],
        chain: CHAIN_2_1,
    },
    Vector {
        name: "[1, 2] claimed Poseidon(Poseidon(0, 1), 2), the fold from zero",
        values: &["1", "2"],
        chain: FOLD_FROM_ZERO_1_2,
    },
    Vector {
        name: "[1, 0, 2] claimed the chain of [1]",
        values: &["1", "0", "2"],
        chain: "1",
    },
    Vector {
        name: "[0, 0, 0] claimed the chain of [1]",
        values: &["0", "0", "0"],
        chain: "1",
    },
];

/// A known-answer vector of the protocol's
/// `test-vectors/nonzero_hash_chain.json`.
pub struct SharedVector {
    pub name: String,
    pub values: Vec<Field>,
    pub chain: Field,
}

pub fn shared_vectors() -> Vec<SharedVector> {
    let file: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../test-vectors/nonzero_hash_chain.json"
    ))
    .expect("nonzero hash chain vectors");
    file.get("vectors")
        .and_then(serde_json::Value::as_array)
        .expect("a vector list")
        .iter()
        .map(|row| SharedVector {
            name: row
                .get("name")
                .and_then(serde_json::Value::as_str)
                .expect("a vector name")
                .to_owned(),
            values: row
                .get("inputs")
                .and_then(serde_json::Value::as_array)
                .expect("the vector's inputs")
                .iter()
                .map(|input| element(input.as_str().expect("an input")))
                .collect(),
            chain: element(
                row.get("output")
                    .and_then(serde_json::Value::as_str)
                    .expect("the vector's output"),
            ),
        })
        .collect()
}

fn element(hex: &str) -> Field {
    reference::from_be(
        &hex::decode(hex)
            .expect("a hex element")
            .try_into()
            .expect("a 32-byte element"),
    )
}
