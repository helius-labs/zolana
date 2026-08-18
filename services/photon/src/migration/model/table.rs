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
    RingConfig,
    SourceInstructionTag,
    OutputTree,
    FirstOutputLeafIndex,
    TxViewingPk,
    Salt,
    Proofless,
    MergeViewTag,
}

#[derive(Copy, Clone, Iden)]
pub enum RingConfigs {
    Table,
    RingConfig,
    ProgramId,
    Authority,
    Slot,
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
    // Copied from rings_transactions, like Slot above, so that the tag queries
    // can order by their cursor key without joining. See
    // m20260809_000001_denormalize_rings_output_ordering.
    Signature,
    EventIndex,
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
