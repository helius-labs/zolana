use zk_program_sdk::circuit::Field;

use crate::harness::{
    field::{field, MODULUS_MINUS_1},
    fixture::Named,
};

pub const CHAIN_1: &str =
    "12583541437132735734108669866114103169564651237895298778035846191048104863326";
pub const CHAIN_1_2: &str =
    "11790059851550142146278072775670916642282838830554510149311470233718605478544";
const CHAIN_2_1: &str =
    "1476778376438626576231939795430560348063838331052242803063935347039248046424";
const POSEIDON_0_0: &str =
    "14744269619966411208579211824598458697587494354926760081771325075741142829156";
const POSEIDON_1_2: &str =
    "7853200120776062878684798364095072458815029376092732009249414926327459813530";

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
        name: "[1] chains to Poseidon(0, 1)",
        values: &["1"],
        chain: CHAIN_1,
    },
    Vector {
        name: "[0, 1] chains as [1]",
        values: &["0", "1"],
        chain: CHAIN_1,
    },
    Vector {
        name: "[1, 0] chains as [1]",
        values: &["1", "0"],
        chain: CHAIN_1,
    },
    Vector {
        name: "[1, 2]",
        values: &["1", "2"],
        chain: CHAIN_1_2,
    },
    Vector {
        name: "[2, 1]",
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
        chain: "20127075603631019434055928315203707068407414306847615530687456290565086592967",
    },
    Vector {
        name: "[5, 0, 7]",
        values: &["5", "0", "7"],
        chain: "9572656188103754034905130542621416082418787987342461347325156076056910674607",
    },
    Vector {
        name: "[p - 1]",
        values: &[MODULUS_MINUS_1],
        chain: "18408546291162903352980960740361656607192922946056016208256932944581138225340",
    },
    Vector {
        name: "[1, 2, 3, 4]",
        values: &["1", "2", "3", "4"],
        chain: "2961510082795718370565764606082963141649148245355877322840462878011704136563",
    },
];

pub const INVALID: [Vector; 7] = [
    Vector {
        name: "[1] claimed 0",
        values: &["1"],
        chain: "0",
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
        name: "[1, 0, 2] claimed the chain of [1]",
        values: &["1", "0", "2"],
        chain: CHAIN_1,
    },
    Vector {
        name: "[1, 2] claimed Poseidon(1, 2)",
        values: &["1", "2"],
        chain: POSEIDON_1_2,
    },
    Vector {
        name: "[0, 0, 0] claimed the chain of [1]",
        values: &["0", "0", "0"],
        chain: CHAIN_1,
    },
];
