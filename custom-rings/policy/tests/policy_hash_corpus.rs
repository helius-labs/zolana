//! The policy hash corpus `prover/server/custom_rings/circuits/policy/corpus_test.go` re-hashes.

use serde::{Deserialize, Serialize};
use solana_address::Address;
use zolana_ring_policy::{
    registry_field, ListId, ListSet, Member, OutflowLimit, Rule, RuleTable, SourceMap, Subject,
    POLICY_VERSION,
};

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/policy-hash-corpus.json"
);
const CASES: usize = 32;
const SUBJECTS: [Subject; 3] = [Subject::OutputOwner, Subject::Sender, Subject::Asset];

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct Corpus {
    version: u8,
    cases: Vec<Case>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
struct Case {
    sources: Vec<Source>,
    rules: Vec<Row>,
    inline_assets: Vec<String>,
    inline_limits: Vec<u64>,
    limits: Vec<LimitCase>,
    policy_hash: String,
}

/// `registry` is the field of a curator registry address, zero for an own list.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
struct Source {
    list_id: u8,
    registry: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
struct Row {
    subject: u8,
    mode: u8,
    mask: u8,
    alt_mask: u8,
    guard_tag: u8,
    threshold: u64,
}

impl Row {
    fn of(rule: &Rule) -> Self {
        let bytes = rule.encoded();
        Self {
            subject: bytes[31],
            mode: bytes[30],
            mask: bytes[29],
            alt_mask: bytes[19],
            guard_tag: bytes[28],
            threshold: u64::from_be_bytes(bytes[20..28].try_into().expect("threshold")),
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
struct LimitCase {
    asset: String,
    cap: u64,
    cosign_above: u64,
}

impl LimitCase {
    fn of(limit: &OutflowLimit) -> Self {
        Self {
            asset: hex::encode(limit.asset),
            cap: limit.cap,
            cosign_above: limit.cosign_above,
        }
    }
}

struct Xorshift(u64);

impl Xorshift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }

    fn bytes(&mut self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for chunk in out.chunks_mut(8) {
            chunk.copy_from_slice(&self.next().to_le_bytes());
        }
        out
    }

    fn lists(&mut self, taken: ListSet) -> ListSet {
        let mut set = ListSet::EMPTY;
        for _ in 0..=self.below(2) {
            let list_id = ListId::ALL[self.below(ListId::ALL.len() as u64) as usize];
            if !taken.contains(list_id) {
                set = set.union(ListSet::single(list_id));
            }
        }
        set
    }

    fn asset(&mut self) -> [u8; 32] {
        *Member::asset(&Address::new_from_array(self.bytes()))
            .expect("asset member")
            .as_bytes()
    }

    fn limits(&mut self) -> Vec<OutflowLimit> {
        let count = 1 + self.below(3) as usize;
        (0..count)
            .map(|_| {
                let bound = 1 + self.below(1 << 40);
                let (cap, cosign_above) = match self.below(3) {
                    0 => (bound, 0),
                    1 => (0, bound),
                    _ => (bound, 1 + self.below(bound)),
                };
                OutflowLimit {
                    asset: self.asset(),
                    cap,
                    cosign_above,
                }
            })
            .collect()
    }
}

fn generate() -> Corpus {
    let mut rng = Xorshift(0x9E37_79B9_7F4A_7C15);
    let mut cases = Vec::new();
    while cases.len() < CASES {
        let mut builder = RuleTable::builder();
        let mut assets: Vec<[u8; 32]> = Vec::new();
        let mut limits: Vec<u64> = Vec::new();
        for _ in 0..=rng.below(3) {
            let subject = SUBJECTS[rng.below(SUBJECTS.len() as u64) as usize];
            let present = rng.lists(ListSet::EMPTY);
            let absent = if rng.below(2) == 0 {
                ListSet::EMPTY
            } else {
                rng.lists(present)
            };
            builder = builder.rule(Rule::any_of(subject, present, absent));
        }
        match rng.below(4) {
            0 => {}
            1 => {
                let count = 1 + rng.below(3) as usize;
                assets = (0..count).map(|_| rng.asset()).collect();
                builder = builder.rule(Rule::allow_only_assets());
            }
            2 => {
                let count = 1 + rng.below(3) as usize;
                assets = (0..count).map(|_| rng.asset()).collect();
                limits = (0..count).map(|_| 1 + rng.below(u64::MAX - 1)).collect();
                let present = rng.lists(ListSet::EMPTY);
                builder =
                    builder.rule(Rule::require_any(Subject::OutputOwner, present).above_by_asset());
            }
            _ => {
                assets = vec![rng.asset()];
                let present = rng.lists(ListSet::EMPTY);
                builder = builder.rule(Rule::allow_only_assets()).rule(
                    Rule::require_any(Subject::OutputOwner, present).above(1 + rng.below(1 << 40)),
                );
            }
        }
        let outflow = if rng.below(3) == 0 {
            Vec::new()
        } else {
            rng.limits()
        };
        let builder = builder
            .inline_assets(&assets)
            .inline_limits(&limits)
            .limits(&outflow);
        let Ok(table) = builder.try_build() else {
            continue;
        };
        // One curator registry at most, every other referenced list is the ring's own.
        let curator = rng.below(2) == 1;
        let curator_registry = registry_field(&rng.bytes()).expect("registry field");
        let registries: Vec<(ListId, [u8; 32])> = table
            .referenced()
            .iter()
            .map(|list_id| {
                let foreign = curator && rng.below(2) == 1;
                (list_id, if foreign { curator_registry } else { [0u8; 32] })
            })
            .collect();
        let sources = SourceMap::new(&registries).expect("positional map");
        let policy_hash = table.encode().hash(&sources).expect("policy hash");
        cases.push(Case {
            sources: sources
                .slots()
                .iter()
                .map(|slot| Source {
                    list_id: slot.list_id,
                    registry: hex::encode(slot.registry),
                })
                .collect(),
            rules: table.rules().iter().map(Row::of).collect(),
            inline_assets: assets.iter().map(hex::encode).collect(),
            inline_limits: limits,
            limits: table.limits().iter().map(LimitCase::of).collect(),
            policy_hash: hex::encode(policy_hash),
        });
    }
    Corpus {
        version: POLICY_VERSION,
        cases,
    }
}

#[test]
fn the_corpus_fixture_is_the_generated_corpus() {
    let corpus = generate();
    if std::env::var_os("WRITE_POLICY_HASH_CORPUS").is_some() {
        std::fs::write(
            FIXTURE,
            serde_json::to_string_pretty(&corpus).expect("json") + "\n",
        )
        .expect("write fixture");
    }
    let stored: Corpus =
        serde_json::from_str(&std::fs::read_to_string(FIXTURE).expect("fixture")).expect("json");
    assert_eq!(stored, corpus, "run with WRITE_POLICY_HASH_CORPUS=1");
}
