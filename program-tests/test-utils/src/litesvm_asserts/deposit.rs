//! Post-instruction checks for `deposit` (SOL deposits).

use solana_pubkey::Pubkey;
use zolana_hasher::Poseidon;
use zolana_interface::instruction::{deposit_blinding, AssetDeposit};
use zolana_interface::{pda, state::STATE_HEIGHT};
use zolana_merkle_tree::MerkleTree;
use zolana_program_test::{DepositOutput, ZolanaProgramTest};
use zolana_transaction::{ProofInputUtxo, SyncWalletAuthority, Wallet, SOL_MINT};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolDepositSnapshot {
    root: [u8; 32],
    indexer_root: [u8; 32],
    indexed_outputs: usize,
    depositor_lamports: u64,
    vault_lamports: u64,
}

impl SolDepositSnapshot {
    pub fn capture(program_test: &ZolanaProgramTest, tree: &Pubkey, depositor: &Pubkey) -> Self {
        Self {
            root: program_test.state_root(tree).expect("state root"),
            indexer_root: program_test.indexer().root(),
            indexed_outputs: program_test.indexer().utxos().len(),
            depositor_lamports: account_lamports(program_test, depositor),
            vault_lamports: account_lamports(program_test, &pda::sol_interface()),
        }
    }

    #[track_caller]
    pub fn assert_accepted(&self, after: &Self, amount: u64) {
        assert_ne!(after.root, self.root, "accepted deposit advances the tree");
        assert_eq!(
            after.indexer_root, after.root,
            "reference indexer follows the on-chain tree"
        );
        assert_eq!(
            after.indexed_outputs,
            self.indexed_outputs + 1,
            "accepted deposit creates exactly one indexed output"
        );
        assert_eq!(
            after.depositor_lamports,
            self.depositor_lamports - amount,
            "depositor pays exactly the modeled amount"
        );
        assert_eq!(
            after.vault_lamports,
            self.vault_lamports + amount,
            "SOL vault receives exactly the modeled amount"
        );
    }

    #[track_caller]
    pub fn assert_rejected(&self, after: &Self) {
        assert_eq!(
            after, self,
            "rejected deposit changes modeled balances, roots, or indexed outputs"
        );
    }
}

#[derive(Clone, Debug)]
struct ExpectedSolDeposit {
    view_tag: [u8; 32],
    owner: [u8; 32],
    blinding: [u8; 32],
    amount: u64,
    memo: Option<Vec<u8>>,
    utxo_hash: [u8; 32],
}

/// Independent expected-state ledger for a sequence of proofless SOL deposits.
///
/// Tests feed accepted transitions into this model, then compare the complete
/// observable state against it after every action. The model does not call the
/// production deposit builder or recompute state from emitted events.
pub struct SolDepositOracle {
    tree: Pubkey,
    initial: SolDepositSnapshot,
    accepted: Vec<ExpectedSolDeposit>,
    expected_tree: MerkleTree<Poseidon>,
}

impl SolDepositOracle {
    pub fn capture(program_test: &ZolanaProgramTest, tree: &Pubkey, depositor: &Pubkey) -> Self {
        let initial = SolDepositSnapshot::capture(program_test, tree, depositor);
        let mut expected_tree = MerkleTree::<Poseidon>::new(STATE_HEIGHT, 0);
        for indexed in program_test.indexer().utxos() {
            expected_tree
                .append(&indexed.utxo_hash)
                .expect("seed expected deposit tree");
        }
        assert_eq!(
            expected_tree.root(),
            initial.root,
            "expected deposit tree matches initial on-chain root"
        );
        Self {
            tree: *tree,
            initial,
            accepted: Vec::new(),
            expected_tree,
        }
    }

    #[track_caller]
    pub fn record_accepted(&mut self, data: &AssetDeposit, event: &DepositOutput) {
        let expected_leaf = self.initial.indexed_outputs + self.accepted.len();
        let data_hash = data
            .utxo_data
            .as_ref()
            .map_or([0u8; 32], |utxo_data| utxo_data.data_hash);
        // Recomputed rather than echoed: the depositor supplies no blinding, SPP
        // derives it from the tree and the leaf index the output lands at.
        let expected_blinding = deposit_blinding(&self.tree.to_bytes(), expected_leaf as u64)
            .expect("model deposit blinding");
        let expected_hash =
            ProofInputUtxo::new(data.owner, &SOL_MINT, data.amount, &expected_blinding)
                .expect("model deposit fields")
                .with_data_hash(data_hash)
                .hash()
                .expect("model deposit hash");
        assert_eq!(event.leaf_index, expected_leaf as u64, "event leaf order");
        assert_eq!(event.utxo_hash, expected_hash, "event UTXO hash");
        assert_eq!(event.view_tag, data.view_tag, "event view tag");
        assert_eq!(event.output.owner, data.owner, "event owner");
        assert_eq!(event.output.blinding, expected_blinding, "event blinding");
        assert_eq!(event.output.amount, data.amount, "event amount");
        assert_eq!(event.output.asset, [0u8; 32], "SOL event asset");
        assert_eq!(event.output.memo, data.memo, "event memo");
        self.accepted.push(ExpectedSolDeposit {
            view_tag: data.view_tag,
            owner: data.owner,
            blinding: expected_blinding,
            amount: data.amount,
            memo: data.memo.clone(),
            utxo_hash: expected_hash,
        });
        self.expected_tree
            .append(&expected_hash)
            .expect("append modeled deposit leaf");
    }

    #[track_caller]
    pub fn assert_matches(
        &self,
        program_test: &ZolanaProgramTest,
        tree: &Pubkey,
        depositor: &Pubkey,
    ) {
        let actual = SolDepositSnapshot::capture(program_test, tree, depositor);
        let total: u64 = self.accepted.iter().map(|deposit| deposit.amount).sum();
        assert_eq!(
            actual.depositor_lamports,
            self.initial.depositor_lamports - total,
            "modeled depositor balance"
        );
        assert_eq!(
            actual.vault_lamports,
            self.initial.vault_lamports + total,
            "modeled SOL vault balance"
        );
        assert_eq!(
            actual.root,
            self.expected_tree.root(),
            "on-chain root matches independently modeled deposit tree"
        );
        assert_eq!(
            actual.indexer_root,
            self.expected_tree.root(),
            "indexer root matches independently modeled deposit tree"
        );
        assert_eq!(
            actual.indexed_outputs,
            self.initial.indexed_outputs + self.accepted.len(),
            "modeled output count"
        );

        let indexed = program_test
            .indexer()
            .utxos()
            .get(self.initial.indexed_outputs..)
            .expect("indexer holds at least the initially indexed outputs");
        assert_eq!(
            indexed.len(),
            self.accepted.len(),
            "modeled indexed records"
        );
        for (offset, (actual, expected)) in indexed.iter().zip(&self.accepted).enumerate() {
            let payload = actual.proofless().expect("modeled proofless payload");
            assert_eq!(
                actual.leaf_index,
                (self.initial.indexed_outputs + offset) as u64,
                "modeled leaf index {offset}"
            );
            assert_eq!(
                actual.view_tag, expected.view_tag,
                "modeled view tag {offset}"
            );
            assert_eq!(
                actual.utxo_hash, expected.utxo_hash,
                "modeled hash {offset}"
            );
            assert_eq!(payload.owner, expected.owner, "modeled owner {offset}");
            assert_eq!(
                payload.blinding, expected.blinding,
                "modeled blinding {offset}"
            );
            assert_eq!(payload.amount, expected.amount, "modeled amount {offset}");
            assert_eq!(payload.asset, [0u8; 32], "modeled SOL asset {offset}");
            assert_eq!(payload.memo, expected.memo, "modeled memo {offset}");
        }
    }
}

fn account_lamports(program_test: &ZolanaProgramTest, key: &Pubkey) -> u64 {
    program_test
        .svm
        .get_account(key)
        .map_or(0, |account| account.lamports)
}

/// Verify a settled SOL `deposit` against the integration-test
/// expectations: the emitted event faithfully mirrors the instruction data and
/// the settled amount, the state tree advanced, the in-memory indexer agrees
/// with the on-chain root, the recipient view tag locates exactly one deposit,
/// and the recipient wallet discovers the new UTXO.
///
/// `root_before` is the on-chain state root captured before the deposit.
pub struct DepositAssertArgs<'a, A: ?Sized> {
    pub tree: &'a Pubkey,
    pub event: &'a DepositOutput,
    pub data: &'a AssetDeposit,
    pub expected_amount: u64,
    pub expected_asset: [u8; 32],
    pub root_before: [u8; 32],
    /// Indexed-output count captured before the deposit, so the expected leaf
    /// index (and the blinding SPP derives from it) never comes from the event
    /// under test. Keyed on the event, this assert could not catch a wrong leaf
    /// index.
    pub indexed_outputs_before: usize,
    pub authority: &'a A,
}

#[track_caller]
pub fn litesvm_assert_deposit<A: SyncWalletAuthority + ?Sized>(
    program_test: &mut ZolanaProgramTest,
    recipient: &mut Wallet,
    args: DepositAssertArgs<'_, A>,
) {
    let DepositAssertArgs {
        tree,
        event,
        data,
        expected_amount,
        expected_asset,
        root_before,
        indexed_outputs_before,
        authority,
    } = args;
    let expected_leaf_index = indexed_outputs_before as u64;
    assert_eq!(event.output.amount, expected_amount, "event amount");
    assert_eq!(event.output.asset, expected_asset, "event asset");
    assert_eq!(event.output.owner, data.owner, "owner");
    assert_eq!(event.view_tag, data.view_tag, "view tag");
    assert_eq!(event.leaf_index, expected_leaf_index, "leaf index");
    assert_eq!(
        event.output.blinding,
        deposit_blinding(&tree.to_bytes(), expected_leaf_index).expect("expected deposit blinding"),
        "blinding"
    );
    assert_eq!(
        event.output.memo, data.memo,
        "event memo mirrors instruction data"
    );

    let root_after = program_test.state_root(tree).expect("state root");
    assert_ne!(root_after, root_before, "leaf must be appended");
    assert_eq!(
        program_test.indexer().root(),
        root_after,
        "indexer root must track the on-chain root"
    );

    let by_tag: Vec<_> = program_test
        .indexer()
        .fetch_by_view_tag(&data.view_tag)
        .collect();
    assert_eq!(by_tag.len(), 1, "recipient view tag locates the deposit");
    let indexed = by_tag.first().expect("one indexed deposit");
    assert_eq!(
        indexed.proofless().expect("proofless deposit").owner,
        data.owner,
        "indexed record owner"
    );

    crate::wallet_discovery::assert_wallet_discovers(
        recipient,
        authority,
        event,
        solana_signature::Signature::default(),
        &data.memo,
        None,
        "deposit",
    );
}
