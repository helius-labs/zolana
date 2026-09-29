use zk_program_sdk::circuit::Field;

use crate::harness::{
    field::{decimal, field, MODULUS_MINUS_1, TWO_POW_253, TWO_POW_64},
    fixture::Named,
};

const X: &str = "12345678901234567890123456789012345678901234567890123456789012345678901234567";
const MINUS_X: &str =
    "9542563970604707332122948956244929409647129832525910886909191840896907261050";
const P1: &str = MODULUS_MINUS_1;

const HASH_1: &str =
    "18586133768512220936620570745912940619677854269274689475585506675881198879027";
pub const HASH_1_2: &str =
    "7853200120776062878684798364095072458815029376092732009249414926327459813530";
const HASH_2_1: &str =
    "9708419728795563670286566418307042748092204899363634976546883453490873071450";
const HASH_1_TO_11: &str =
    "3572015662710076994097916907865950486270383304442561406230608893458731714472";
const HASH_0_0: &str =
    "14744269619966411208579211824598458697587494354926760081771325075741142829156";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vector {
    pub name: &'static str,
    pub inputs: &'static [&'static str],
    pub hash: &'static str,
}

impl Named for Vector {
    fn name(&self) -> &'static str {
        self.name
    }
}

impl Vector {
    pub fn inputs(&self) -> Vec<Field> {
        self.inputs.iter().map(|input| field(input)).collect()
    }

    pub fn hash(&self) -> Field {
        field(self.hash)
    }

    pub fn arity(&self) -> usize {
        self.inputs.len()
    }

    pub fn circom(&self, hash: Field) -> Vec<(&'static str, Vec<String>)> {
        vec![
            (
                "inputs",
                self.inputs.iter().map(|input| input.to_string()).collect(),
            ),
            ("hash", vec![decimal(hash)]),
        ]
    }
}

/// Poseidon(1, 2, ..., n) for every supported arity n, first in arity order,
/// then the edge vectors.
pub const VALID: [Vector; 20] = [
    Vector {
        name: "Poseidon(1)",
        inputs: &["1"],
        hash: HASH_1,
    },
    Vector {
        name: "Poseidon(1, 2)",
        inputs: &["1", "2"],
        hash: HASH_1_2,
    },
    Vector {
        name: "Poseidon(1, ..., 3)",
        inputs: &["1", "2", "3"],
        hash: "6542985608222806190361240322586112750744169038454362455181422643027100751666",
    },
    Vector {
        name: "Poseidon(1, ..., 4)",
        inputs: &["1", "2", "3", "4"],
        hash: "18821383157269793795438455681495246036402687001665670618754263018637548127333",
    },
    Vector {
        name: "Poseidon(1, ..., 5)",
        inputs: &["1", "2", "3", "4", "5"],
        hash: "6183221330272524995739186171720101788151706631170188140075976616310159254464",
    },
    Vector {
        name: "Poseidon(1, ..., 6)",
        inputs: &["1", "2", "3", "4", "5", "6"],
        hash: "20400040500897583745843009878988256314335038853985262692600694741116813247201",
    },
    Vector {
        name: "Poseidon(1, ..., 7)",
        inputs: &["1", "2", "3", "4", "5", "6", "7"],
        hash: "12748163991115452309045839028154629052133952896122405799815156419278439301912",
    },
    Vector {
        name: "Poseidon(1, ..., 8)",
        inputs: &["1", "2", "3", "4", "5", "6", "7", "8"],
        hash: "18604317144381847857886385684060986177838410221561136253933256952257712543953",
    },
    Vector {
        name: "Poseidon(1, ..., 9)",
        inputs: &["1", "2", "3", "4", "5", "6", "7", "8", "9"],
        hash: "13589767895268936107593642967621470491511464502761040466226072462545218539640",
    },
    Vector {
        name: "Poseidon(1, ..., 10)",
        inputs: &["1", "2", "3", "4", "5", "6", "7", "8", "9", "10"],
        hash: "3657500514307717306974218405144578736633140001277925127187636780142269815841",
    },
    Vector {
        name: "Poseidon(1, ..., 11)",
        inputs: &["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11"],
        hash: HASH_1_TO_11,
    },
    Vector {
        name: "Poseidon(1, ..., 12)",
        inputs: &[
            "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12",
        ],
        hash: "2501997477381648492950318384533644783248002172679259592360114615426357826485",
    },
    Vector {
        name: "Poseidon(0)",
        inputs: &["0"],
        hash: "19014214495641488759237505126948346942972912379615652741039992445865937985820",
    },
    Vector {
        name: "Poseidon(p - 1)",
        inputs: &[P1],
        hash: "3366645945435192953002076803303112651887535928162668198103357554665518664470",
    },
    Vector {
        name: "Poseidon(0, 0)",
        inputs: &["0", "0"],
        hash: HASH_0_0,
    },
    Vector {
        name: "Poseidon(p - 1, p - 1)",
        inputs: &[P1, P1],
        hash: "20092309280547939997162506796691455192771288143174894022739895715370814071035",
    },
    Vector {
        name: "Poseidon(x, -x)",
        inputs: &[X, MINUS_X],
        hash: "17676089653672588639115080643066226413411782258097775715987297692798613162112",
    },
    Vector {
        name: "Poseidon(2^64, 2^253)",
        inputs: &[TWO_POW_64, TWO_POW_253],
        hash: "19488182497941627518654251004602109371986726907912769001719418047615246913234",
    },
    Vector {
        name: "Poseidon(0 x 12)",
        inputs: &["0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
        hash: "9360644637339281731404031769602981527812191049496204724644500187104347980883",
    },
    Vector {
        name: "Poseidon((p - 1) x 12)",
        inputs: &[P1, P1, P1, P1, P1, P1, P1, P1, P1, P1, P1, P1],
        hash: "19954545845259530224833196457776832669602840150862728308568673102687953039531",
    },
];

pub const INVALID: [Vector; 6] = [
    Vector {
        name: "Poseidon(1, 2) claimed 0",
        inputs: &["1", "2"],
        hash: "0",
    },
    Vector {
        name: "Poseidon(1, 2) claimed Poseidon(2, 1)",
        inputs: &["1", "2"],
        hash: HASH_2_1,
    },
    Vector {
        name: "Poseidon(1, 2) claimed Poseidon(1, 2) + 1",
        inputs: &["1", "2"],
        hash: "7853200120776062878684798364095072458815029376092732009249414926327459813531",
    },
    Vector {
        name: "Poseidon(1) claimed Poseidon(1, 2)",
        inputs: &["1"],
        hash: HASH_1_2,
    },
    Vector {
        name: "Poseidon(0, 0) claimed 0",
        inputs: &["0", "0"],
        hash: "0",
    },
    Vector {
        name: "Poseidon(1, ..., 12) claimed Poseidon(1, ..., 11)",
        inputs: &[
            "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12",
        ],
        hash: HASH_1_TO_11,
    },
];

pub fn by_arity(arity: usize) -> Vector {
    VALID[arity - 1]
}
