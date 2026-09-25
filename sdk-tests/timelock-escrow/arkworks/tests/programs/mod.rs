use timelock_escrow_arkworks::{
    Escrow, EscrowPrivateInputs, EscrowPublicInputs, EscrowTerms, Withdraw, WithdrawPrivateInputs,
    WithdrawPublicInputs,
};
use timelock_escrow_sdk::escrow_authority;
use zk_program_sdk::{Owner, TxContext};
use zolana_hasher::primitives::solana_owner_identity;

use crate::shared::{escrow_utxo, keypair, token_input, token_inputs};

pub const UNLOCK: u64 = 1_700_000_000;

pub fn escrow() -> Escrow {
    let creator = keypair(5);
    let address = creator.shielded_address().expect("creator address");
    Escrow {
        private: EscrowPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: token_inputs([
                token_input(&creator, 600, 0),
                token_input(&creator, 400, 1),
            ]),
            unlock: UNLOCK,
            amount: 250,
        },
        public: EscrowPublicInputs {
            escrow_owner: escrow_authority()
                .address(address.viewing_pubkey)
                .expect("escrow owner"),
        },
    }
}

pub fn withdraw() -> Withdraw {
    let creator = keypair(5);
    let address = creator.shielded_address().expect("creator address");
    Withdraw {
        private: WithdrawPrivateInputs {
            tx_context: TxContext::new(),
            escrow: escrow_utxo(&creator, 250, UNLOCK),
            terms: EscrowTerms {
                creator: Owner::try_from(&address).expect("creator owner"),
                unlock: UNLOCK,
            },
        },
        public: WithdrawPublicInputs {
            unlock: UNLOCK,
            owner_identity: solana_owner_identity(
                address.solana_address().expect("creator").as_array(),
            )
            .expect("owner identity"),
        },
    }
}
