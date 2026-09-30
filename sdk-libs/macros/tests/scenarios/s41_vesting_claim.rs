use borsh::{BorshDeserialize, BorshSerialize};
use zolana_keypair::ShieldedAddress;
use zolana_program::{
    circuit::{
        Assert, CheckedTransaction, Circuit, CircuitType, ConfidentialTransaction, DataUtxo,
        PublicInputs, TokenUtxos, UtxoTrait,
    },
    conversion::ProofInput,
    CircuitError, Groth16Prover, TxContext, ZkProgram,
};
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    shared::{keypair, refused, ProgramOwner},
};

fn vesting_authority() -> ProgramOwner {
    ProgramOwner::new(43)
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, CircuitType)]
pub struct Vesting {
    pub beneficiary_hash: [u8; 32],
    pub total: u64,
    pub claimed: u64,
    pub start: u64,
    pub end: u64,
}

#[derive(Clone, ProofInput)]
pub struct VestingClaim {
    private: VestingClaimPrivateInputs,
    public: VestingClaimPublicInputs,
}

#[derive(Clone, ProofInput)]
struct VestingClaimPrivateInputs {
    tx_context: TxContext,
    vesting: WalletUtxo,
    state: Vesting,
    beneficiary: ShieldedAddress,
    vesting_owner: ShieldedAddress,
}

#[derive(Clone, PublicInputs)]
struct VestingClaimPublicInputs {
    now: u64,
    start: u64,
    end: u64,
}

#[deny(clippy::disallowed_types)]
impl Circuit for <VestingClaim as ProofInput>::Circuit {
    fn circuit(&self) -> Result<CheckedTransaction, CircuitError> {
        let private = &self.private;
        let public = &self.public;
        let mut vesting = DataUtxo::new_close(&private.vesting, &private.state)?;
        private.beneficiary.hash()?.assert_equal(
            &vesting.beneficiary_hash,
            "the claimant is not the beneficiary",
        )?;
        private.vesting_owner.hash()?.assert_equal(
            &vesting.owner().hash()?,
            "the vesting owner is not the pool's",
        )?;
        public
            .start
            .assert_equal(&vesting.start, "the start is not the schedule's")?;
        public
            .end
            .assert_equal(&vesting.end, "the end is not the schedule's")?;
        let elapsed = public
            .now
            .checked_sub(&public.start, "the vesting has not started")?;
        let remaining = public
            .end
            .checked_sub(&public.now, "the vesting has ended")?;
        let duration = elapsed.add::<65>(&remaining);
        let (unlocked, _remainder) = vesting.total.mul::<128>(&elapsed).div_rem::<64, _>(
            &duration,
            "the unlocked amount is not total * elapsed / duration",
        )?;
        let payout = unlocked.checked_sub(
            &vesting.claimed,
            "the claim is below what was already claimed",
        )?;
        let mut paid = TokenUtxos::new_init(&private.beneficiary, &vesting.asset());
        vesting.transfer(&mut paid, &payout)?;
        let mut next = DataUtxo::<VestingCircuit>::new_init(&private.vesting_owner)
            .with_asset(&vesting.asset())?;
        vesting.transfer_all(&mut next)?;
        next.beneficiary_hash = vesting.beneficiary_hash.clone();
        next.total = vesting.total.clone();
        next.claimed = unlocked;
        next.start = vesting.start.clone();
        next.end = vesting.end.clone();

        ConfidentialTransaction::new(&private.tx_context, public)
            .with_data_utxo(vesting)
            .with_token_utxos(paid)
            .with_data_utxo(next)
            .check()
    }
}

#[test]
fn vesting_claim_prove_and_verify() {
    let beneficiary = keypair(5);
    let address = beneficiary.shielded_address().expect("beneficiary address");
    let payer = address.solana_address().expect("payer");
    let vesting_owner = vesting_authority().address(&address);
    let state = Vesting {
        beneficiary_hash: address.owner_hash().expect("beneficiary hash"),
        total: 1_000,
        claimed: 100,
        start: 1_000,
        end: 1_700,
    };
    let vesting = vesting_authority().data_input(&address, Mint::SOL, 900, &state, 0);

    let claim = VestingClaim {
        private: VestingClaimPrivateInputs {
            tx_context: TxContext::new(),
            vesting,
            state: state.clone(),
            beneficiary: address,
            vesting_owner,
        },
        public: VestingClaimPublicInputs {
            now: 1_300,
            start: 1_000,
            end: 1_700,
        },
    };
    let spp_proof_inputs = claim
        .create_proof_inputs_and_encrypt_with_keys(&beneficiary, payer, u64::MAX)
        .expect("vesting claim proof inputs");
    assert_eq!(
        spp_proof_inputs
            .output_utxos
            .iter()
            .map(|output| (
                output.owner_address,
                output.asset,
                output.amount,
                output.data.utxo_data().map(<[u8]>::to_vec),
            ))
            .collect::<Vec<_>>(),
        vec![
            (Some(address), Mint::SOL, 328, None),
            (
                Some(vesting_owner),
                Mint::SOL,
                572,
                Some(
                    borsh::to_vec(&Vesting {
                        claimed: 428,
                        ..state
                    })
                    .expect("vesting bytes")
                ),
            ),
        ]
    );

    let prover = Groth16Prover::<VestingClaim>::new_with_test_setup().expect("vesting claim setup");
    let result = prove(&prover, &claim, "vesting claim proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}

#[test]
fn a_claim_outside_the_schedule_or_over_an_empty_one_is_refused() {
    let beneficiary = keypair(5);
    let address = beneficiary.shielded_address().expect("beneficiary address");
    let claim = |start: u64, end: u64, now: u64| {
        let state = Vesting {
            beneficiary_hash: address.owner_hash().expect("beneficiary hash"),
            total: 1_000,
            claimed: 0,
            start,
            end,
        };
        VestingClaim {
            private: VestingClaimPrivateInputs {
                tx_context: TxContext::new(),
                vesting: vesting_authority().data_input(&address, Mint::SOL, 1_000, &state, 0),
                state,
                beneficiary: address,
                vesting_owner: vesting_authority().address(&address),
            },
            public: VestingClaimPublicInputs { now, start, end },
        }
    };

    assert_eq!(
        [
            refused(&claim(1_000, 1_700, 900)),
            refused(&claim(1_000, 1_700, 1_800)),
            refused(&claim(1_000, 1_000, 1_000)),
        ],
        [
            (Some("the vesting has not started".to_string()), true),
            (Some("the vesting has ended".to_string()), true),
            (
                Some("the unlocked amount is not total * elapsed / duration".to_string()),
                true
            ),
        ]
    );
}
