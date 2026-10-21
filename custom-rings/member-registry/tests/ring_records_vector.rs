//! `test-vectors/ring-records.json`, record queue writes as the program receives them and
//! the applications that fold them into the tree, read by the apply circuit and Photon.

use custom_ring_interface::{
    queue_chain, EscrowKey, QueueEntry, RecordWriteData, WriteRecordsIxData,
    MEMBER_REGISTRY_EMPTY_ROOT,
};
use serde::{Deserialize, Serialize};
use zolana_hasher::primitives::{hash_bytes, solana_owner_identity};
use zolana_ring_member_registry::{
    MemberRecord, MemberRegistryTree, QuadPath, RecordOpening, RecordTree, RecordWriteProofInput,
    ZERO_SUBTREES,
};
use zolana_ring_policy::{ListId, ListSet, ListWrite, Writer};

const VECTORS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../test-vectors/ring-records.json"
);

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct RecordVectors {
    description: String,
    empty_root: String,
    zero_subtrees: Vec<String>,
    applications: Vec<Application>,
    openings: Vec<Opening>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct Application {
    name: String,
    /// `apply_records` or `authority_write_records`.
    instruction: String,
    /// Queued by earlier instructions, in queue order.
    pending: Vec<QueuedWrite>,
    /// Queued by the instruction itself behind the pending writes.
    authority_writes: Vec<QueuedWrite>,
    old_root: String,
    new_root: String,
    old_next_index: u64,
    new_next_index: u64,
    chain_start: String,
    chain_end: String,
    count: u64,
    statement_hash: String,
    /// Proof inputs per write, queue order.
    writes: Vec<WriteInput>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct QueuedWrite {
    position: u64,
    /// `member_write`, `register_key` or `authority_write`.
    kind: String,
    /// The member's signing key, `member` is its owner identity.
    signer: Option<String>,
    member: String,
    mask: u64,
    value: u64,
    nullifier_pk: Option<String>,
    eph_u: Option<String>,
    ciphertext: Option<String>,
    escrow_key: String,
    entry_hash: String,
    /// `chain(position)`.
    chain: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct WriteInput {
    member: String,
    mask: u64,
    value: u64,
    escrow_key: String,
    exists: bool,
    old_next: String,
    old_lists: u64,
    old_escrow: String,
    slot: Path,
    low: Record,
    low_path: Path,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct Record {
    member: String,
    next: String,
    lists: u64,
    escrow_key: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct Path {
    index: u64,
    siblings: Vec<Vec<String>>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct Opening {
    member: String,
    root: String,
    present: bool,
    /// The member's record, or the low record bracketing an absent member.
    record: Record,
    path: Path,
}

/// One write as an instruction queues it.
enum Queued {
    Member {
        signer: [u8; 32],
        write: ListSet,
        clear: ListSet,
    },
    Key {
        signer: [u8; 32],
        nullifier_pk: [u8; 32],
        eph_u: [u8; 32],
        ciphertext: [u8; 32],
    },
    Authority {
        member: [u8; 32],
        set: ListSet,
        clear: ListSet,
    },
}

impl Queued {
    fn entry(&self) -> QueueEntry {
        let lists = |set: ListSet, clear: ListSet| {
            WriteRecordsIxData::new(ListWrite::new(set, clear).expect("list write"))
        };
        match self {
            Self::Member {
                signer,
                write,
                clear,
            } => lists(*write, *clear)
                .entry(identity(signer), Writer::Member)
                .expect("member write"),
            Self::Key {
                signer,
                nullifier_pk,
                ciphertext,
                ..
            } => QueueEntry::escrow(
                identity(signer),
                &EscrowKey {
                    nullifier_pk,
                    ciphertext,
                },
            )
            .expect("escrow write"),
            Self::Authority { member, set, clear } => RecordWriteData {
                member: *member,
                lists: lists(*set, *clear),
            }
            .entry()
            .expect("authority write"),
        }
    }

    fn vector(&self, position: u64, entry: &QueueEntry, chain: &[u8; 32]) -> QueuedWrite {
        let (kind, signer, key) = match self {
            Self::Member { signer, .. } => ("member_write", Some(signer), None),
            Self::Key {
                signer,
                nullifier_pk,
                eph_u,
                ciphertext,
            } => (
                "register_key",
                Some(signer),
                Some((nullifier_pk, eph_u, ciphertext)),
            ),
            Self::Authority { .. } => ("authority_write", None, None),
        };
        QueuedWrite {
            position,
            kind: kind.to_string(),
            signer: signer.map(hex::encode),
            member: hex::encode(entry.member),
            mask: entry.mask,
            value: entry.value,
            nullifier_pk: key.map(|(pk, _, _)| hex::encode(pk)),
            eph_u: key.map(|(_, eph_u, _)| hex::encode(eph_u)),
            ciphertext: key.map(|(_, _, ciphertext)| hex::encode(ciphertext)),
            escrow_key: hex::encode(entry.escrow_key),
            entry_hash: hex::encode(entry.hash().expect("entry hash")),
            chain: hex::encode(chain),
        }
    }
}

fn identity(signer: &[u8; 32]) -> [u8; 32] {
    solana_owner_identity(signer).expect("owner identity")
}

fn lists(lists: &[ListId]) -> ListSet {
    ListSet::of(lists)
}

fn signer(seed: u8) -> [u8; 32] {
    [seed; 32]
}

fn asset(seed: u8) -> [u8; 32] {
    hash_bytes(&[seed; 32]).expect("asset field")
}

fn key(signer_seed: u8, key_seed: u8) -> Queued {
    Queued::Key {
        signer: signer(signer_seed),
        nullifier_pk: hash_bytes(&[key_seed; 32]).expect("nullifier key"),
        eph_u: [key_seed ^ 0x66; 32],
        ciphertext: [key_seed ^ 0x77; 32],
    }
}

/// The queue and the tree the applications run over.
struct Registry {
    tree: MemberRegistryTree,
    position: u64,
    /// `chain(tail - 1)`.
    chain: [u8; 32],
    /// `chain(head - 1)`.
    chain_head: [u8; 32],
    pending: Vec<(QueueEntry, QueuedWrite)>,
}

impl Registry {
    fn new() -> Self {
        Self {
            tree: MemberRegistryTree::new().expect("tree"),
            position: 0,
            chain: [0; 32],
            chain_head: [0; 32],
            pending: Vec::new(),
        }
    }

    fn queue(&mut self, queued: Queued) -> (QueueEntry, QueuedWrite) {
        let entry = queued.entry();
        self.chain = queue_chain(&self.chain, &entry).expect("chain");
        let vector = queued.vector(self.position, &entry, &self.chain);
        self.position += 1;
        (entry, vector)
    }

    fn write(&mut self, queued: Queued) {
        let write = self.queue(queued);
        self.pending.push(write);
    }

    /// Every pending write, then the instruction's own authority writes.
    fn apply(&mut self, name: &str, authority: Vec<Queued>) -> Application {
        let pending = std::mem::take(&mut self.pending);
        let authority_writes: Vec<_> = authority
            .into_iter()
            .map(|queued| self.queue(queued))
            .collect();
        let entries: Vec<QueueEntry> = pending
            .iter()
            .chain(&authority_writes)
            .map(|(entry, _)| *entry)
            .collect();
        let inputs = self
            .tree
            .apply(self.chain_head, &entries)
            .expect("application");
        assert_eq!(inputs.chain_end, self.chain);
        self.chain_head = self.chain;
        let statement = inputs.statement().expect("statement");
        let instruction = match authority_writes.is_empty() {
            true => "apply_records",
            false => "authority_write_records",
        };
        Application {
            name: name.to_string(),
            instruction: instruction.to_string(),
            pending: pending.into_iter().map(|(_, vector)| vector).collect(),
            authority_writes: authority_writes
                .into_iter()
                .map(|(_, vector)| vector)
                .collect(),
            old_root: hex::encode(inputs.old_root),
            new_root: hex::encode(inputs.new_root),
            old_next_index: inputs.old_next_index,
            new_next_index: inputs.new_next_index,
            chain_start: hex::encode(inputs.chain_start),
            chain_end: hex::encode(inputs.chain_end),
            count: statement.count,
            statement_hash: hex::encode(statement.hash().expect("statement hash")),
            writes: inputs.writes.iter().map(write_input).collect(),
        }
    }

    fn opening(&self, member: &[u8; 32]) -> Opening {
        let root = self.tree.root().expect("root");
        let opening = self.tree.opening(member).expect("opening");
        assert!(opening.verify(&root, member).is_ok());
        let (present, record, path) = match opening {
            RecordOpening::Present { record, path } => (true, record, path),
            RecordOpening::Absent { low, path } => (false, low, path),
        };
        Opening {
            member: hex::encode(member),
            root: hex::encode(root),
            present,
            record: record_vector(&record),
            path: path_vector(&path),
        }
    }
}

fn write_input(input: &RecordWriteProofInput) -> WriteInput {
    WriteInput {
        member: hex::encode(input.entry.member),
        mask: input.entry.mask,
        value: input.entry.value,
        escrow_key: hex::encode(input.entry.escrow_key),
        exists: input.exists,
        old_next: hex::encode(input.old_next),
        old_lists: input.old_lists,
        old_escrow: hex::encode(input.old_escrow),
        slot: path_vector(&input.slot),
        low: record_vector(&input.low),
        low_path: path_vector(&input.low_path),
    }
}

fn record_vector(record: &MemberRecord) -> Record {
    Record {
        member: hex::encode(record.member),
        next: hex::encode(record.next),
        lists: record.lists,
        escrow_key: hex::encode(record.escrow_key),
    }
}

fn path_vector(path: &QuadPath) -> Path {
    Path {
        index: path.index,
        siblings: path
            .siblings
            .iter()
            .map(|level| level.iter().map(hex::encode).collect())
            .collect(),
    }
}

fn compute_vectors() -> RecordVectors {
    use ListId::{Allow, Approval, Block, Frozen, Reader, Recovery, RingViewing};
    let mut registry = Registry::new();
    let none = ListSet::EMPTY;
    // Both members insert past the sentinel, the second after the first relinked it.
    let first = registry.apply(
        "authority_inserts_after_a_relink",
        vec![
            Queued::Authority {
                member: identity(&signer(0x21)),
                set: lists(&[Allow]),
                clear: none,
            },
            Queued::Authority {
                member: asset(0x31),
                set: lists(&[Allow, Reader]),
                clear: none,
            },
            Queued::Authority {
                member: identity(&signer(0x22)),
                set: lists(&[Block]),
                clear: none,
            },
        ],
    );
    registry.write(Queued::Member {
        signer: signer(0x21),
        write: lists(&[RingViewing]),
        clear: none,
    });
    registry.write(key(0x23, 0x61));
    registry.write(key(0x23, 0x62));
    registry.write(Queued::Member {
        signer: signer(0x24),
        write: none,
        clear: lists(&[Recovery]),
    });
    registry.write(Queued::Member {
        signer: signer(0x21),
        write: lists(&[Recovery]),
        clear: lists(&[RingViewing]),
    });
    let members = registry.apply("member_writes_updates_escrow_and_no_op", Vec::new());
    for seed in 0x40..0x48 {
        registry.write(Queued::Member {
            signer: signer(seed),
            write: lists(&[RingViewing]),
            clear: none,
        });
    }
    let authority = (0x50..0x58)
        .map(|seed| Queued::Authority {
            member: match seed % 2 {
                0 => identity(&signer(seed)),
                _ => identity(&signer(seed - 0x10)),
            },
            set: lists(&[Frozen, Approval]),
            clear: lists(&[Allow]),
        })
        .collect();
    let full = registry.apply("full_batch_of_member_and_authority_writes", authority);
    let openings = [
        identity(&signer(0x21)),
        asset(0x31),
        identity(&signer(0x24)),
    ]
    .iter()
    .map(|member| registry.opening(member))
    .collect();
    RecordVectors {
        description: "Record queue writes as the ring program receives them and the \
                      applications that fold them into the 4-ary member record tree. A \
                      member or register-key write's member is owner_identity(signer), an \
                      escrow key is Poseidon(nullifier_pk, hash_bytes(ciphertext)), an entry \
                      hash is Poseidon(CRQW, member, mask, value, escrow_key) and chain(p) = \
                      Poseidon(chain(p - 1), entry_p) from chain(-1) = 0. The writes of an \
                      application are its pending writes then its authority writes, each with \
                      the apply circuit's proof inputs. Paths list three siblings per level, \
                      leaf level first, in ascending child order. Produced by \
                      custom-rings/member-registry/tests/ring_records_vector.rs."
            .to_string(),
        empty_root: hex::encode(MEMBER_REGISTRY_EMPTY_ROOT),
        zero_subtrees: ZERO_SUBTREES.iter().map(hex::encode).collect(),
        applications: vec![first, members, full],
        openings,
    }
}

#[test]
fn ring_records_vector() {
    let committed: RecordVectors =
        serde_json::from_str(&std::fs::read_to_string(VECTORS).expect("vector file"))
            .expect("vector json");
    assert_eq!(committed, compute_vectors());
}

#[test]
#[ignore = "rewrites test-vectors/ring-records.json"]
fn write_ring_records_vector() {
    let json = serde_json::to_string_pretty(&compute_vectors()).expect("json");
    std::fs::write(VECTORS, json + "\n").expect("write vector file");
}
