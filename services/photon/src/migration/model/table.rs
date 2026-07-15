use sea_orm_migration::prelude::*;

#[derive(Copy, Clone, Iden)]
pub enum StateTrees {
    Table,
    Tree,
    TreeKind,
    NodeIdx,
    LeafIdx,
    Level,
    Hash,
    Seq,
}

#[derive(Copy, Clone, Iden)]
pub enum Blocks {
    Table,
    Slot,
    ParentSlot,
    Blockhash,
    ParentBlockhash,
    BlockHeight,
    BlockTime,
}

#[derive(Copy, Clone, Iden)]
pub enum Transactions {
    Table,
    Signature,
    Slot,
    Error,
}

#[derive(Copy, Clone, Iden)]
pub enum IndexedTrees {
    Table,
    Tree,
    LeafIndex,
    Value,
    NextIndex,
    NextValue,
    Seq,
}

#[derive(Copy, Clone, Iden)]
pub enum RingsTransactions {
    Table,
    RingsTxId,
    Signature,
    EventIndex,
    Slot,
    RingsProgramId,
    SourceInstructionTag,
    OutputTree,
    FirstOutputLeafIndex,
    TxViewingPk,
    Salt,
    Proofless,
}

#[derive(Copy, Clone, Iden)]
pub enum RingsTransactionPayloads {
    Table,
    RingsTxId,
    EncryptedUtxos,
    RawEvent,
    ParseVersion,
}

#[derive(Copy, Clone, Iden)]
pub enum RingsOutputs {
    Table,
    OutputId,
    RingsTxId,
    Slot,
    OutputIndex,
    OutputTree,
    LeafIndex,
    ViewTag,
    UtxoHash,
}

#[derive(Copy, Clone, Iden)]
pub enum RingsOutputPayloads {
    Table,
    OutputId,
    Payload,
}

#[derive(Copy, Clone, Iden)]
pub enum RingsMessages {
    Table,
    MessageId,
    RingsTxId,
    Slot,
    MessageIndex,
    ViewTag,
    Payload,
}

#[derive(Copy, Clone, Iden)]
pub enum RingsTxNullifiers {
    Table,
    NullifierId,
    RingsTxId,
    Slot,
    InputIndex,
    NullifierTree,
    InputQueueSeq,
    Nullifier,
}
