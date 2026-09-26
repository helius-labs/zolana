//! Wallet action and transaction-boundary tests against finalized proof inputs.

#[path = "../../client/tests/common/input.rs"]
mod input_fixture;
#[path = "../../client/tests/test_indexer.rs"]
mod test_indexer;
#[path = "../../client/tests/common/transfer.rs"]
mod transfer_fixture;

use borsh::BorshDeserialize;
use input_fixture::wallet_utxo;
use solana_address::Address;
use solana_pubkey::Pubkey;
use std::sync::atomic::{AtomicUsize, Ordering};
use test_indexer::TestIndexer;
use transfer_fixture::transfer_prover;
use zolana_client::{AsyncRpc, ClientError, Rpc, TransferProver};
use zolana_event::OutputDataEncoding;
use zolana_interface::{instruction::TransactProof, pda, SOL_ASSET_FIELD};
use zolana_keypair::{NullifierKey, ShieldedKeypair, SigningKey, ViewingKey};
use zolana_transaction::{
    instructions::transact::{
        signed_magnitude_to_field, ConfidentialTransaction, SettlementTransfer, Shape,
        SppProofInputs,
    },
    serialization::confidential::{Confidential, ConfidentialOutputPlaintext},
    utxo::{derive_output_blinding_seed, derive_transact_output_blinding},
    AssetRegistry, Data, Mint, SppProofOutputUtxo, TransactionError, Utxo, WalletUtxo, SOL_MINT,
};
use zolana_wallet::{
    create_transfer, create_withdrawal, sign_shielded_transaction, AnonymousRecipientSlot,
    ApprovalRequest, EncryptedTransfer, KeypairWalletAuthority, P256Signature, SyncWalletAuthority,
    TransferParams, Wallet, WalletAuthority, WithdrawalLeg, WithdrawalParams,
};

fn test_keypair() -> ShieldedKeypair {
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(
        &zolana_keypair::random_blinding(),
    ))
    .unwrap()
}

fn input(owner: &ShieldedKeypair, asset: Mint, amount: u64) -> WalletUtxo {
    wallet_utxo(
        Utxo {
            owner: owner.signing_pubkey(),
            asset,
            amount,
            blinding: zolana_keypair::random_blinding(),
            ring_program_id: None,
            data: Data::default(),
        },
        &owner.nullifier_key,
        0,
        0,
        None,
        None,
    )
}

fn transaction(sender: &ShieldedKeypair, amount: u64) -> ConfidentialTransaction {
    ConfidentialTransaction::new(vec![input(sender, Mint::SOL, amount)], Address::default())
        .unwrap()
}

fn sign(
    mut tx: ConfidentialTransaction,
    sender: &ShieldedKeypair,
    shape: Shape,
) -> Result<SppProofInputs, TransactionError> {
    tx.pad_utxos(shape, &sender.shielded_address().unwrap())?;
    tx.encrypt(sender)
}

fn prover_of(mut tx: SppProofInputs) -> TransferProver {
    let mut indexer = TestIndexer::new();
    for input in tx.input_utxos.iter_mut().filter(|input| !input.is_dummy()) {
        input.leaf_index = indexer.add_utxo(input.utxo_hash);
    }
    let proofs = indexer
        .get_input_merkle_proofs(&tx.input_utxo_hashes().unwrap(), None)
        .unwrap();
    let dummy: Vec<_> = tx
        .dummy_nullifiers()
        .into_iter()
        .map(|nf| indexer.dummy_nullifier_proof(nf))
        .collect();
    transfer_prover(tx, &proofs, &dummy)
}

fn assert_outputs(
    tx: &SppProofInputs,
    sender: &ShieldedKeypair,
    expected: &[(zolana_keypair::ShieldedAddress, Mint, u64)],
) {
    assert_eq!(tx.output_utxos.len(), expected.len());
    let first = tx.first_nullifier().unwrap();
    let seed = derive_output_blinding_seed(&first, &tx.blinding_seed).unwrap();
    let viewing_key = sender.get_transaction_viewing_key(&first).unwrap();
    for (index, ((output, encoded), (owner, asset, amount))) in tx
        .output_utxos
        .iter()
        .zip(&tx.external_data.outputs)
        .zip(expected)
        .enumerate()
    {
        let blinding = derive_transact_output_blinding(&first, &seed, index as u32).unwrap();
        assert_eq!(
            (
                output.owner_address,
                output.asset,
                output.amount,
                output.blinding
            ),
            (Some(*owner), *asset, *amount, blinding)
        );
        assert_eq!(encoded.utxo_hash, output.hash(tx.output_tree_id).unwrap());
        assert_eq!(
            tx.external_data.resolved_owner_tags[index],
            owner.signing_pubkey.confidential_view_tag().unwrap()
        );
        let OutputDataEncoding::Encrypted(blob) =
            OutputDataEncoding::try_from_slice(encoded.data.as_ref().unwrap()).unwrap()
        else {
            panic!("ciphertext expected")
        };
        assert_eq!(
            Confidential::embedded_viewing_pk(&blob[1..]).unwrap(),
            owner.viewing_pubkey
        );
        assert_eq!(
            Confidential::decrypt_with_tx_key(
                &viewing_key,
                &blob[1..],
                tx.external_data.salt,
                index as u32
            )
            .unwrap(),
            ConfidentialOutputPlaintext {
                asset_id: asset.asset_id,
                amount: *amount,
                blinding,
                ring_program_id: None,
                data: Data::default(),
            }
        );
    }
}

#[test]
fn transfer_round_trip_outputs_and_slots() {
    let sender = test_keypair();
    let recipient = test_keypair();
    let mut tx = transaction(&sender, 100);
    tx.transfer_sol(&recipient.shielded_address().unwrap(), 60)
        .unwrap();
    let tx = sign(tx, &sender, Shape::IN2_OUT3).unwrap();
    assert_outputs(
        &tx,
        &sender,
        &[
            (recipient.shielded_address().unwrap(), Mint::SOL, 60),
            (sender.shielded_address().unwrap(), Mint::SOL, 40),
            (sender.shielded_address().unwrap(), Mint::SOL, 0),
        ],
    );
    assert!(tx.external_data.interface_transfers.is_empty());
    assert_eq!(
        tx.public_transfers().unwrap(),
        zolana_client::PublicTransfers::default()
    );
    prover_of(tx).build().unwrap();
}

#[test]
fn dummy_output_ciphertexts_are_indistinguishable_from_real() {
    let sender = test_keypair();
    let recipient = test_keypair();
    let without = sign(transaction(&sender, 100), &sender, Shape::IN2_OUT3).unwrap();
    let mut with = transaction(&sender, 100);
    with.transfer_sol(&recipient.shielded_address().unwrap(), 60)
        .unwrap();
    let with = sign(with, &sender, Shape::IN2_OUT3).unwrap();
    let sizes = |tx: &SppProofInputs| {
        tx.external_data
            .outputs
            .iter()
            .map(|o| o.data.as_ref().unwrap().len())
            .collect::<Vec<_>>()
    };
    assert_eq!(sizes(&without), sizes(&with));
    assert!(sizes(&with).iter().all(|n| *n > 0));
    assert!(without
        .output_utxos
        .iter()
        .all(|output| output.owner_address.is_some()));
}

#[test]
fn assemble_carries_ciphertext_and_decrypts() {
    let sender = test_keypair();
    let recipient = test_keypair();
    let mut tx = transaction(&sender, 100);
    tx.transfer_sol(&recipient.shielded_address().unwrap(), 60)
        .unwrap();
    let tx = sign(tx, &sender, Shape::IN2_OUT3).unwrap();
    let mut indexer = TestIndexer::new();
    indexer.add_utxo(tx.input_utxos[0].utxo_hash);
    let proofs = indexer
        .get_input_merkle_proofs(&tx.input_utxo_hashes().unwrap(), None)
        .unwrap();
    let dummy: Vec<_> = tx
        .dummy_nullifiers()
        .into_iter()
        .map(|nf| indexer.dummy_nullifier_proof(nf))
        .collect();
    let assembled = zolana_client::assemble(tx.clone(), &proofs, &dummy).unwrap();
    let ix = assembled.with_proof(TransactProof::zeroed());
    assert_eq!(ix.outputs, tx.external_data.outputs);
    assert_eq!(ix.salt, tx.external_data.salt);
    assert_eq!(ix.tx_viewing_pk, tx.external_data.tx_viewing_pk);
    assert_eq!(
        ix.inputs
            .iter()
            .map(|i| i.nullifier_hash)
            .collect::<Vec<_>>(),
        tx.input_utxos
            .iter()
            .map(|i| i.nullifier)
            .collect::<Vec<_>>()
    );
    assert_outputs(
        &tx,
        &sender,
        &[
            (recipient.shielded_address().unwrap(), Mint::SOL, 60),
            (sender.shielded_address().unwrap(), Mint::SOL, 40),
            (sender.shielded_address().unwrap(), Mint::SOL, 0),
        ],
    );
}

#[test]
fn withdrawal_sets_external_data_and_change() {
    let sender = test_keypair();
    let recipient = Address::new_unique();
    let mut tx = transaction(&sender, 100);
    tx.withdraw_sol(60, recipient).unwrap();
    let tx = sign(tx, &sender, Shape::IN1_OUT2).unwrap();
    assert_eq!(
        tx.external_data.interface_transfers,
        vec![SettlementTransfer::Sol {
            is_deposit: false,
            amount: 60,
            user_sol_account: recipient
        }]
    );
    let transfers = tx.public_transfers().unwrap();
    assert_eq!(transfers.assets[0], SOL_ASSET_FIELD);
    assert_eq!(transfers.amounts[0], signed_magnitude_to_field(false, 60));
    assert_outputs(
        &tx,
        &sender,
        &[
            (sender.shielded_address().unwrap(), Mint::SOL, 40),
            (sender.shielded_address().unwrap(), Mint::SOL, 0),
        ],
    );
}

#[test]
fn default_transact_rejects_p256_and_uses_eddsa() {
    let sender = ShieldedKeypair::new_p256().unwrap();
    assert!(matches!(
        sign(transaction(&sender, 10), &sender, Shape::IN1_OUT2),
        Err(TransactionError::P256TransactUnsupported)
    ));
    let sender = test_keypair();
    let tx = transaction(&sender, 10);
    assert!(!tx.requires_p256_owner().unwrap());
    prover_of(sign(tx, &sender, Shape::IN1_OUT2).unwrap())
        .build()
        .unwrap();
}

#[test]
fn input_commitments_include_data_and_ring_hashes() {
    let sender = test_keypair();
    let original = input(&sender, Mint::SOL, 100);
    let note = wallet_utxo(
        original.utxo,
        &sender.nullifier_key,
        0,
        0,
        Some([11; 32]),
        Some([12; 32]),
    );
    let expected = (note.utxo_hash, note.nullifier);
    let tx = ConfidentialTransaction::new(vec![note], Address::default())
        .unwrap()
        .encrypt(&sender)
        .unwrap();
    assert_eq!(
        (tx.input_utxos[0].utxo_hash, tx.input_utxos[0].nullifier),
        expected
    );
}

#[test]
fn a_transaction_without_inputs_is_refused() {
    assert!(matches!(
        ConfidentialTransaction::new(vec![], Address::default()),
        Err(TransactionError::NoInputs)
    ));
}

#[test]
fn oversend_is_insufficient_balance() {
    let sender = test_keypair();
    let recipient = test_keypair();
    let mut tx = transaction(&sender, 100);
    tx.transfer_sol(&recipient.shielded_address().unwrap(), 200)
        .unwrap();
    assert!(matches!(
        sign(tx, &sender, Shape::IN2_OUT3),
        Err(TransactionError::InsufficientBalance {
            requested: 100,
            available: 0
        })
    ));
}

#[test]
fn repeated_withdrawals_are_preserved() {
    let sender = test_keypair();
    let mut tx = transaction(&sender, 100);
    tx.withdraw_sol(10, Address::default())
        .unwrap()
        .withdraw_sol(5, Address::default())
        .unwrap();
    assert_eq!(tx.public_transfers().len(), 2);
    let signed = tx.encrypt(&sender).unwrap();
    assert_eq!(signed.external_data.interface_transfers.len(), 2);
    assert_eq!(
        signed.public_transfers().unwrap().amounts[0],
        signed_magnitude_to_field(false, 15)
    );
}

#[test]
fn two_distinct_spl_assets_and_sol_are_supported() {
    let sender = test_keypair();
    let recipient = test_keypair();
    let assets = [
        Mint::SOL,
        Mint {
            asset: Address::new_unique(),
            asset_id: 2,
        },
        Mint {
            asset: Address::new_unique(),
            asset_id: 3,
        },
    ];
    let notes = assets.map(|asset| input(&sender, asset, 10));
    let mut tx = ConfidentialTransaction::new(notes.to_vec(), Address::default()).unwrap();
    tx.transfer_sol(&recipient.shielded_address().unwrap(), 10)
        .unwrap();
    for asset in &assets[1..] {
        tx.transfer(&recipient.shielded_address().unwrap(), asset.asset, 10)
            .unwrap();
    }
    let tx = tx.encrypt(&sender).unwrap();
    assert_eq!(tx.check_shape().unwrap(), Shape::IN3_OUT3);
    assert_eq!(
        tx.output_utxos.iter().map(|o| o.asset).collect::<Vec<_>>(),
        assets
    );
}
struct AsyncTestAuthority {
    keypair: ShieldedKeypair,
    approvals: AtomicUsize,
    p256_sign_calls: AtomicUsize,
}

#[async_trait::async_trait]
impl WalletAuthority for AsyncTestAuthority {
    fn solana_pubkey(&self) -> Address {
        Address::default()
    }

    async fn shielded_address(
        &self,
    ) -> Result<zolana_keypair::shielded::ShieldedAddress, TransactionError> {
        SyncWalletAuthority::shielded_address(&KeypairWalletAuthority::new(
            self.solana_pubkey(),
            &self.keypair,
        ))
    }

    async fn viewing_keys(&self) -> Result<Vec<ViewingKey>, TransactionError> {
        Ok(vec![self.keypair.viewing_key.clone()])
    }

    async fn encrypt_confidential_transfer(
        &self,
        first_nullifier: &[u8; 32],
        outputs: &[SppProofOutputUtxo],
    ) -> Result<EncryptedTransfer, TransactionError> {
        SyncWalletAuthority::encrypt_confidential_transfer(
            &KeypairWalletAuthority::new(self.solana_pubkey(), &self.keypair),
            first_nullifier,
            outputs,
        )
    }

    async fn encrypt_anonymous_transfer(
        &self,
        first_nullifier: &[u8; 32],
        sender_view_tag: [u8; 32],
        sender: &zolana_transaction::serialization::anonymous::AnonymousTransferSenderPlaintext,
        recipients: &[AnonymousRecipientSlot],
    ) -> Result<zolana_wallet::EncryptedTransfer, TransactionError> {
        SyncWalletAuthority::encrypt_anonymous_transfer(
            &KeypairWalletAuthority::new(self.solana_pubkey(), &self.keypair),
            first_nullifier,
            sender_view_tag,
            sender,
            recipients,
        )
    }

    async fn request_user_approval(
        &self,
        request: ApprovalRequest,
    ) -> Result<(), TransactionError> {
        assert_eq!(request.solana_pubkey, self.solana_pubkey());
        assert!(request.summary.contains("private transaction"));
        self.approvals.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn sign_p256(&self, message_hash: &[u8; 32]) -> Result<P256Signature, TransactionError> {
        self.p256_sign_calls.fetch_add(1, Ordering::SeqCst);
        SyncWalletAuthority::sign_p256(
            &KeypairWalletAuthority::new(self.solana_pubkey(), &self.keypair),
            message_hash,
        )
    }

    async fn spend_nullifier_key(&self) -> Result<NullifierKey, TransactionError> {
        SyncWalletAuthority::spend_nullifier_key(&KeypairWalletAuthority::new(
            self.solana_pubkey(),
            &self.keypair,
        ))
    }
}

#[test]
fn async_authority_invokes_approval_without_p256_signing() {
    let sender = test_keypair();
    let authority = AsyncTestAuthority {
        keypair: sender.clone(),
        approvals: AtomicUsize::new(0),
        p256_sign_calls: AtomicUsize::new(0),
    };
    let mut wallet =
        Wallet::new(sender.shielded_address().unwrap(), AssetRegistry::default()).unwrap();
    wallet.utxos.push(input(&sender, Mint::SOL, 100));
    let unsigned = create_withdrawal(WithdrawalParams {
        wallet: &wallet,
        payer: Address::default(),
        legs: vec![WithdrawalLeg {
            recipient: Pubkey::new_unique(),
            asset: SOL_MINT,
            amount: 60,
            spl_token_program: Some(zolana_interface::pda::spl_token_program_id()),
        }],
    })
    .expect("created")
    .transaction;
    let signed =
        futures::executor::block_on(sign_shielded_transaction(unsigned, &wallet, &authority))
            .unwrap();

    assert_eq!(authority.approvals.load(Ordering::SeqCst), 1);
    assert_eq!(authority.p256_sign_calls.load(Ordering::SeqCst), 0);
    prover_of(signed.transaction).build().unwrap();
}

#[tokio::test]
async fn create_transfer_builds_withdrawal_when_recipient_unregistered() {
    use solana_account::Account;
    use zolana_transaction::{Data, Utxo, SOL_MINT};

    struct RegistryAbsent;

    impl Rpc for RegistryAbsent {
        fn get_account(&self, _address: Address) -> Result<Option<Account>, ClientError> {
            Ok(None)
        }
    }

    #[async_trait::async_trait]
    impl AsyncRpc for RegistryAbsent {
        async fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
            Rpc::get_account(self, address)
        }
    }

    let sender = test_keypair();
    let mut wallet = Wallet::new(
        sender.shielded_address().expect("shielded address"),
        AssetRegistry::default(),
    )
    .expect("wallet");
    let utxo = Utxo {
        owner: sender.signing_pubkey(),
        asset: zolana_transaction::Mint::SOL,
        amount: 10,
        blinding: {
            let mut blinding = [7u8; 32];
            blinding[0] = 0;
            blinding
        },
        ring_program_id: None,
        data: Data::default(),
    };
    let nullifier_pk = sender.nullifier_key.pubkey().expect("nullifier pubkey");
    let hash = utxo
        .hash(&nullifier_pk, &[0u8; 32], &[0u8; 32], 0)
        .expect("utxo hash");
    let nullifier = utxo
        .nullifier(&hash, &sender.nullifier_key)
        .expect("nullifier");
    wallet.utxos.push(WalletUtxo {
        utxo,
        nullifier_pubkey: nullifier_pk,
        utxo_hash: hash,
        nullifier,
        data_hash: None,
        ring_data_hash: None,
        tree_id: 0,
        leaf_index: 0,

        slot: 0,
        tx_signature: solana_signature::Signature::default(),
        slot_index: 0,
    });

    let recipient = Pubkey::new_unique();
    let rpc = RegistryAbsent;
    let created = create_transfer(TransferParams {
        rpc: &rpc,
        wallet: &wallet,
        payer: Address::default(),
        recipient,
        asset: SOL_MINT,
        amount: 1,
    })
    .await
    .expect("async create transfer");

    assert!(created.recipient.is_public_withdrawal());
    assert_eq!(created.transaction.tree(), pda::tree(0));
}
