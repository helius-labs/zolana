use crate::harness::fixture::Named;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vector {
    pub name: &'static str,
    pub deposit: u64,
    pub amount: u64,
    pub balances: [u64; 2],
}

impl Named for Vector {
    fn name(&self) -> &'static str {
        self.name
    }
}

impl Vector {
    pub fn off_by_one(&self) -> Self {
        let [source, destination] = self.balances;
        Self {
            balances: [source ^ 1, destination],
            ..*self
        }
    }
}

const MAX: u64 = u64::MAX;

pub const TRANSFERS: [Vector; 4] = [
    Vector {
        name: "10 moves 4",
        deposit: 10,
        amount: 4,
        balances: [6, 4],
    },
    Vector {
        name: "1 moves 0",
        deposit: 1,
        amount: 0,
        balances: [1, 0],
    },
    Vector {
        name: "7 moves all 7",
        deposit: 7,
        amount: 7,
        balances: [0, 7],
    },
    Vector {
        name: "2^64 - 1 moves 2^64 - 1",
        deposit: MAX,
        amount: MAX,
        balances: [0, MAX],
    },
];

pub const TRANSFER_ALLS: [Vector; 2] = [
    Vector {
        name: "10 moves the whole 10",
        deposit: 10,
        amount: 0,
        balances: [0, 10],
    },
    Vector {
        name: "2^64 - 1 moves the whole 2^64 - 1",
        deposit: MAX,
        amount: 0,
        balances: [0, MAX],
    },
];

pub const WITHDRAWALS: [Vector; 3] = [
    Vector {
        name: "10 withdraws 3",
        deposit: 10,
        amount: 3,
        balances: [7, 0],
    },
    Vector {
        name: "5 withdraws all 5",
        deposit: 5,
        amount: 5,
        balances: [0, 0],
    },
    Vector {
        name: "2^64 - 1 withdraws 1",
        deposit: MAX,
        amount: 1,
        balances: [MAX - 1, 0],
    },
];

pub const WITHDRAW_ALLS: [Vector; 2] = [
    Vector {
        name: "10 withdraws the whole 10",
        deposit: 10,
        amount: 10,
        balances: [0, 0],
    },
    Vector {
        name: "2^64 - 1 withdraws the whole 2^64 - 1",
        deposit: MAX,
        amount: MAX,
        balances: [0, 0],
    },
];

pub const EXCEEDING: [Vector; 3] = [
    Vector {
        name: "10 moves 11",
        deposit: 10,
        amount: 11,
        balances: [0, 0],
    },
    Vector {
        name: "1 moves 2^64 - 1",
        deposit: 1,
        amount: MAX,
        balances: [0, 0],
    },
    Vector {
        name: "2^64 - 2 moves 2^64 - 1",
        deposit: MAX - 1,
        amount: MAX,
        balances: [0, 0],
    },
];

pub const ZERO_DEPOSIT: Vector = Vector {
    name: "0 deposited",
    deposit: 0,
    amount: 0,
    balances: [0, 0],
};

pub const ZERO_WITHDRAWAL: Vector = Vector {
    name: "5 withdraws 0",
    deposit: 5,
    amount: 0,
    balances: [5, 0],
};
