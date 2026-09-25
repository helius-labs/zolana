use borsh::{BorshDeserialize, BorshSerialize};
use zk_program_sdk::{
    circuit,
    circuit::{
        constant, Assert, Balance, CheckedTransaction, Circuit, CircuitType,
        ConfidentialTransaction, DataUtxo, PublicInputs, TokenUtxo,
    },
    conversion::ProofInput,
    Groth16Prover, RelationError, TxContext, ZkProgram,
};
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    shared::{keypair, ProgramOwner},
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
struct VestingClaim {
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
    unlocked: u64,
    remainder: u64,
}

#[derive(Clone, ProofInput, PublicInputs)]
struct VestingClaimPublicInputs {
    now: u64,
    start: u64,
    end: u64,
}

#[circuit]
impl Circuit for VestingClaim {
    fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
        let private = &self.private;
        let public = &self.public;
        let mut vesting = DataUtxo::new_burn(&private.vesting, &private.state)?;
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
        let elapsed = public.now.clone() - &public.start;
        elapsed.check_bits(64)?;
        (public.end.clone() - &public.now).check_bits(64)?;
        let duration = public.end.clone() - &public.start;
        (private.unlocked.clone() * &duration + &private.remainder).assert_equal(
            &(vesting.total.clone() * &elapsed),
            "the unlocked amount is not total * elapsed / duration",
        )?;
        (duration - &private.remainder - constant(1u64)).check_bits(64)?;
        let payout = private.unlocked.clone() - &vesting.claimed;
        let mut paid = TokenUtxo::new_init(&private.beneficiary, &vesting.asset());
        vesting.transfer(&mut paid, &payout)?;
        let mut next =
            DataUtxo::<VestingCircuit>::new_init(&private.vesting_owner, &vesting.asset());
        vesting.transfer_all(&mut next)?;
        next.beneficiary_hash = vesting.beneficiary_hash.clone();
        next.total = vesting.total.clone();
        next.claimed = private.unlocked.clone();
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
            unlocked: 428,
            remainder: 400,
        },
        public: VestingClaimPublicInputs {
            now: 1_300,
            start: 1_000,
            end: 1_700,
        },
    };
    let spp_proof_inputs = claim
        .create_proof_inputs_and_encrypt(&beneficiary, payer, u64::MAX)
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
