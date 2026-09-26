use zk_program_sdk::{
    circuit,
    circuit::{
        constant, poseidon, Assert, Balance, Bits, CheckedTransaction, Circuit,
        ConfidentialTransaction, DataUtxo, PublicInputs,
    },
    conversion::ProofInput,
    Groth16Prover, RelationError, TxContext, ZkProgram,
};
use zolana_hasher::primitives::right_align;
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    s42_create_poll::{poll_authority, poll_utxo, Poll},
    shared::{keypair, poseidon_bytes, MerklePath, MerkleTree},
};

#[derive(Clone, ProofInput)]
struct CastVote {
    private: CastVotePrivateInputs,
    public: CastVotePublicInputs,
}

#[derive(Clone, ProofInput)]
struct CastVotePrivateInputs {
    tx_context: TxContext,
    poll: WalletUtxo,
    state: Poll,
    poll_owner: ShieldedAddress,
    choice: u64,
    secret_key: [u8; 32],
    path: MerklePath,
}

#[derive(Clone, ProofInput, PublicInputs)]
struct CastVotePublicInputs {
    poll_id: u64,
    root: [u8; 32],
    nullifier: [u8; 32],
}

#[circuit]
impl Circuit for CastVote {
    fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
        let private = &self.private;
        let public = &self.public;
        let mut poll = DataUtxo::new_mut(&private.poll, &private.state)?;
        private
            .poll_owner
            .hash()?
            .assert_equal(&poll.owner().hash()?, "the poll owner is not the poll's")?;
        public
            .poll_id
            .assert_equal(&poll.poll_id, "the poll id is not the poll's")?;
        public
            .root
            .assert_equal(&poll.root, "the voter root is not the poll's")?;
        private.choice.check_bits(2)?;
        private
            .choice
            .assert_not_equal(&constant(3u64), "the choice is not an option")?;
        private
            .path
            .root(&poseidon(std::slice::from_ref(&private.secret_key))?)?
            .assert_equal(&public.root, "the voter is not registered")?;
        poseidon(&[public.poll_id.clone(), private.secret_key.clone()])?
            .assert_equal(&public.nullifier, "the nullifier is not the voter's")?;
        for (tally, option) in poll.tally.iter_mut().zip(0u64..) {
            *tally = private
                .choice
                .is_equal(&constant(option))?
                .select(&(tally.clone() + constant(1u64)), tally);
        }

        ConfidentialTransaction::new(&private.tx_context, public)
            .with_data_utxo(poll)
            .check()
    }
}

#[test]
fn cast_vote_prove_and_verify() {
    let creator = keypair(5);
    let creator_address = creator.shielded_address().expect("creator address");
    let voter = keypair(6);
    let address = voter.shielded_address().expect("voter address");
    let payer = address.solana_address().expect("payer");
    let secret_key = [4u8; 32];
    let voters = MerkleTree::new(&[
        poseidon_bytes(&[[1u8; 32]]),
        poseidon_bytes(&[[2u8; 32]]),
        poseidon_bytes(&[secret_key]),
    ]);
    let (poll, state) = poll_utxo(&creator, 3, voters.root());
    let poll_owner = poll_authority().address(&creator_address);

    let vote = CastVote {
        private: CastVotePrivateInputs {
            tx_context: TxContext::new(),
            poll,
            state: state.clone(),
            poll_owner,
            choice: 1,
            secret_key,
            path: voters.path(2),
        },
        public: CastVotePublicInputs {
            poll_id: 3,
            root: voters.root(),
            nullifier: poseidon_bytes(&[right_align(&3u64.to_be_bytes()), secret_key]),
        },
    };
    let spp_proof_inputs = vote
        .create_proof_inputs_and_encrypt(&voter, payer, u64::MAX)
        .expect("vote proof inputs");
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
        vec![(
            Some(poll_owner),
            Mint::SOL,
            0,
            Some(
                borsh::to_vec(&Poll {
                    tally: [0, 1, 0],
                    ..state
                })
                .expect("poll bytes")
            ),
        )]
    );

    let prover = Groth16Prover::<CastVote>::new_with_test_setup().expect("vote setup");
    let result = prove(&prover, &vote, "vote proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
