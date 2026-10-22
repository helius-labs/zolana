//! `test-vectors/ring-policy-table.json`, the table hash the policy circuits and the SDKs recompute.

use serde::{Deserialize, Serialize};
use solana_address::Address;
use zolana_ring_policy::{
    registry_field, EncodedRuleTable, Guard, ListId, ListSet, Member, Mode, OutflowLimit,
    PolicySource, Rule, RuleSource, RuleTable, SourceMap, Subject, TableParts, MAX_INLINE_ASSETS,
    MAX_OUTFLOW_LIMITS, MAX_RULES, POLICY_TABLE_VERSION,
};

const VECTORS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../test-vectors/ring-policy-table.json"
);
const GENERATED_CASES: usize = 12;
const SUBJECTS: [Subject; 3] = [Subject::OutputOwner, Subject::Sender, Subject::Asset];

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct PolicyTableVectors {
    description: String,
    version: u8,
    cases: Vec<Case>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct Case {
    name: String,
    sources: Vec<Source>,
    rules: Vec<String>,
    /// `rules[i]` split into its parts.
    rule_parts: Vec<RuleParts>,
    inline_assets: Vec<String>,
    inline_limits: Vec<u64>,
    limits: Vec<Limit>,
    fields: Vec<String>,
    policy_hash: String,
}

/// `registry` is the field of a curator registry address, zero for the ring's own.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct Source {
    list_id: u8,
    registry: String,
}

/// The circuit's split of a row from its low byte, the enumerated parts by name.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct RuleParts {
    #[serde(with = "SubjectName")]
    subject: Subject,
    #[serde(with = "ModeName")]
    mode: Mode,
    mask: u8,
    guard: GuardTag,
    threshold: u64,
    alternative: u8,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "Subject", rename_all = "snake_case")]
enum SubjectName {
    OutputOwner,
    Sender,
    ExitDestination,
    Asset,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "Mode", rename_all = "snake_case")]
enum ModeName {
    Present,
    Absent,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
enum GuardTag {
    Always,
    AboveAmount,
    AboveAmountByAsset,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct Limit {
    asset: String,
    cap: u64,
    cosign_above: u64,
}

impl Case {
    fn source_map(&self) -> SourceMap {
        let slots: Vec<PolicySource> = self.sources.iter().map(Source::slot).collect();
        SourceMap::from_slots(slots.try_into().expect("one source per slot"))
            .expect("positional sources")
    }
}

impl Source {
    fn new(slot: &PolicySource) -> Self {
        Self {
            list_id: slot.list_id,
            registry: hex::encode(slot.registry),
        }
    }

    fn slot(&self) -> PolicySource {
        PolicySource {
            list_id: self.list_id,
            registry: bytes(&self.registry),
        }
    }
}

impl RuleParts {
    /// Read from the rule's subject, lists and guard, never from its row.
    fn new(rule: &Rule) -> Self {
        let RuleSource::Lists { present, absent } = rule.source;
        let mode = rule.primary_mode();
        let (mask, alternative) = match mode {
            Mode::Present => (present, absent),
            Mode::Absent => (absent, ListSet::EMPTY),
        };
        let (guard, threshold) = match rule.guard {
            Guard::Always => (GuardTag::Always, 0),
            Guard::AboveAmount(amount) => (GuardTag::AboveAmount, amount),
            Guard::AboveAmountByAsset => (GuardTag::AboveAmountByAsset, 0),
        };
        Self {
            subject: rule.subject,
            mode,
            mask: mask.bits(),
            guard,
            threshold,
            alternative: alternative.bits(),
        }
    }

    fn rule(&self) -> Rule {
        let (mask, alternative) = (
            ListSet::from_bits(self.mask),
            ListSet::from_bits(self.alternative),
        );
        let rule = match self.mode {
            Mode::Present => Rule::any_of(self.subject, mask, alternative),
            Mode::Absent => Rule::any_of(self.subject, ListSet::EMPTY, mask),
        };
        match self.guard {
            GuardTag::Always => rule,
            GuardTag::AboveAmount => rule.above(self.threshold),
            GuardTag::AboveAmountByAsset => rule.above_by_asset(),
        }
    }
}

impl Limit {
    fn new(limit: &OutflowLimit) -> Self {
        Self {
            asset: hex::encode(limit.asset),
            cap: limit.cap,
            cosign_above: limit.cosign_above,
        }
    }

    fn outflow_limit(&self) -> OutflowLimit {
        OutflowLimit {
            asset: bytes(&self.asset),
            cap: self.cap,
            cosign_above: self.cosign_above,
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
        (0..=self.below(2))
            .map(|_| ListId::ALL[self.below(ListId::ALL.len() as u64) as usize])
            .filter(|list_id| !taken.contains(*list_id))
            .fold(ListSet::EMPTY, |set, list_id| {
                set.union(ListSet::single(list_id))
            })
    }

    fn asset(&mut self) -> [u8; 32] {
        asset(self.bytes())
    }

    fn limits(&mut self, count: usize) -> Vec<OutflowLimit> {
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

    fn table(&mut self) -> Option<RuleTable> {
        let mut builder = RuleTable::builder();
        for _ in 0..=self.below(3) {
            let subject = SUBJECTS[self.below(SUBJECTS.len() as u64) as usize];
            let present = self.lists(ListSet::EMPTY);
            let absent = match self.below(2) {
                0 => ListSet::EMPTY,
                _ => self.lists(present),
            };
            builder = builder.rule(Rule::any_of(subject, present, absent));
        }
        let (mut assets, mut limits) = (Vec::new(), Vec::new());
        match self.below(3) {
            0 => {}
            1 => {
                let count = 1 + self.below(3) as usize;
                assets = (0..count).map(|_| self.asset()).collect();
                limits = (0..count).map(|_| 1 + self.below(u64::MAX - 1)).collect();
                let present = self.lists(ListSet::EMPTY);
                builder =
                    builder.rule(Rule::require_any(Subject::OutputOwner, present).above_by_asset());
            }
            _ => {
                let present = self.lists(ListSet::EMPTY);
                builder = builder.rule(
                    Rule::require_any(Subject::OutputOwner, present).above(1 + self.below(1 << 40)),
                );
            }
        }
        let outflow = match self.below(3) {
            0 => Vec::new(),
            _ => {
                let count = 1 + self.below(3) as usize;
                self.limits(count)
            }
        };
        builder
            .inline_assets(&assets)
            .inline_limits(&limits)
            .limits(&outflow)
            .try_build()
            .ok()
    }

    /// One curator registry at most, every other referenced list is the ring's own.
    fn sources(&mut self, table: &RuleTable) -> SourceMap {
        let curator = self.below(2) == 1;
        let curator_registry = registry_field(&self.bytes()).expect("registry field");
        let entries: Vec<(ListId, [u8; 32])> = table
            .referenced()
            .iter()
            .map(|list_id| match curator && self.below(2) == 1 {
                true => (list_id, curator_registry),
                false => (list_id, [0u8; 32]),
            })
            .collect();
        SourceMap::new(&entries).expect("positional map")
    }
}

/// Every slot filled, the curator serves the odd lists.
fn full_table(rng: &mut Xorshift) -> (RuleTable, SourceMap) {
    let mut builder = RuleTable::builder()
        .rule(Rule::require(Subject::OutputOwner, ListId::Allow).above_by_asset());
    let sender_rules = ListId::ALL
        .into_iter()
        .map(|list_id| Rule::require(Subject::Sender, list_id))
        .chain(
            ListId::ALL
                .into_iter()
                .map(|list_id| Rule::forbid(Subject::Sender, list_id)),
        );
    for rule in sender_rules.take(MAX_RULES - 1) {
        builder = builder.rule(rule);
    }
    let assets: Vec<[u8; 32]> = (0..MAX_INLINE_ASSETS).map(|_| rng.asset()).collect();
    let limits: Vec<u64> = (0..MAX_INLINE_ASSETS as u64).map(|i| 1 + i).collect();
    let outflow = rng.limits(MAX_OUTFLOW_LIMITS);
    let table = builder
        .inline_assets(&assets)
        .inline_limits(&limits)
        .limits(&outflow)
        .build();
    let curator = registry_field(&rng.bytes()).expect("registry field");
    let entries: Vec<(ListId, [u8; 32])> = ListId::ALL
        .into_iter()
        .map(|list_id| match list_id as u8 % 2 {
            1 => (list_id, curator),
            _ => (list_id, [0u8; 32]),
        })
        .collect();
    (table, SourceMap::new(&entries).expect("positional map"))
}

/// Every subject, mode and guard, the top bit of each mask, threshold and bound set.
fn full_width_table() -> (RuleTable, SourceMap) {
    let table = RuleTable::builder()
        .rule(
            Rule::any_of(
                Subject::OutputOwner,
                ListSet::of(&[ListId::Allow, ListId::Frozen]),
                ListSet::of(&[ListId::Block, ListId::Escrow]),
            )
            .above(u64::MAX),
        )
        .rule(Rule::forbid_all(Subject::Sender, ListSet::of(&ListId::ALL)))
        .rule(Rule::any_of(
            Subject::Asset,
            ListSet::single(ListId::Escrow),
            ListSet::of(&ListId::ALL[..7]),
        ))
        .rule(Rule::require(Subject::Asset, ListId::Approval).above(1))
        .rule(
            Rule::require_any(
                Subject::OutputOwner,
                ListSet::of(&[ListId::RingViewing, ListId::Recovery]),
            )
            .above_by_asset(),
        )
        .rule(Rule::forbid(Subject::OutputOwner, ListId::Reader).above(1 << 63))
        .inline_assets(&[asset([0x11; 32]), asset([0x12; 32])])
        .inline_limits(&[1, u64::MAX])
        .limits(&[
            OutflowLimit {
                asset: asset([0x13; 32]),
                cap: u64::MAX,
                cosign_above: 1,
            },
            OutflowLimit {
                asset: asset([0x14; 32]),
                cap: 0,
                cosign_above: u64::MAX,
            },
        ])
        .build();
    let curator = registry_field(&[0x15; 32]).expect("registry field");
    let entries: Vec<(ListId, [u8; 32])> = ListId::ALL
        .into_iter()
        .map(|list_id| match list_id {
            ListId::Block | ListId::Frozen => (list_id, curator),
            _ => (list_id, [0u8; 32]),
        })
        .collect();
    (table, SourceMap::new(&entries).expect("positional map"))
}

fn asset(mint: [u8; 32]) -> [u8; 32] {
    *Member::asset(&Address::new_from_array(mint))
        .expect("asset member")
        .as_bytes()
}

fn bytes(value: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    hex::decode_to_slice(value, &mut out).expect("32-byte hex");
    out
}

fn case(name: &str, table: &RuleTable, sources: &SourceMap) -> Case {
    let encoded: EncodedRuleTable = table.encode();
    assert_eq!(encoded.decode(), Ok(*table));
    Case {
        name: name.to_string(),
        sources: sources.slots().iter().map(Source::new).collect(),
        rules: table
            .rules()
            .iter()
            .map(|rule| hex::encode(rule.encoded()))
            .collect(),
        rule_parts: table.rules().iter().map(RuleParts::new).collect(),
        inline_assets: table.inline_assets().iter().map(hex::encode).collect(),
        inline_limits: table.inline_limits().to_vec(),
        limits: table.limits().iter().map(Limit::new).collect(),
        fields: encoded.fields(sources).iter().map(hex::encode).collect(),
        policy_hash: hex::encode(encoded.hash(sources).expect("policy hash")),
    }
}

fn compute_vectors() -> PolicyTableVectors {
    let mut rng = Xorshift(0x9E37_79B9_7F4A_7C15);
    let (full, full_sources) = full_table(&mut rng);
    let (wide, wide_sources) = full_width_table();
    let mut cases = vec![
        case(
            "empty",
            &RuleTable::builder().build(),
            &SourceMap::default(),
        ),
        case("full_with_curator", &full, &full_sources),
        case("full_width_parts", &wide, &wide_sources),
    ];
    let named = cases.len();
    while cases.len() < named + GENERATED_CASES {
        let Some(table) = rng.table() else {
            continue;
        };
        let sources = rng.sources(&table);
        let name = format!("generated_{}", cases.len() - named);
        cases.push(case(&name, &table, &sources));
    }
    PolicyTableVectors {
        description: "The 77 policy table fields and their hash, acc = 0 then \
                      acc = Poseidon(acc, fields[11c..11c + 11]) for c = 0..7. Fields are \
                      CRTB, the version, list id and registry field per source slot, the rule, \
                      inline and limit counts, 16 rule rows, 8 inline assets, 8 inline limits, \
                      then asset, cap and cosign per limit row, every slot past a count zero. \
                      rule_parts splits each rule row read as one big-endian field from its low \
                      byte, subject, mode, mask and guard one byte each, the u64 threshold, then \
                      the alternative mask, every higher byte zero. Subject output_owner is 1, \
                      sender 2, asset 4, mode present 1, absent 2, guard always 0, above_amount \
                      1, above_amount_by_asset 2, mask bit i is list i + 1. Produced by \
                      custom-rings/policy/tests/policy_table_vector.rs."
            .to_string(),
        version: POLICY_TABLE_VERSION,
        cases,
    }
}

fn committed() -> PolicyTableVectors {
    serde_json::from_str(&std::fs::read_to_string(VECTORS).expect("vector file"))
        .expect("vector json")
}

#[test]
fn ring_policy_table_vector() {
    assert_eq!(committed(), compute_vectors());
}

/// Builds each committed case from its parts and decodes it from its rows.
#[test]
fn ring_policy_table_parts_encode_and_decode() {
    for case in committed().cases {
        let inline_assets: Vec<[u8; 32]> = case
            .inline_assets
            .iter()
            .map(|value| bytes(value))
            .collect();
        let limits: Vec<OutflowLimit> = case.limits.iter().map(Limit::outflow_limit).collect();
        let built = case
            .rule_parts
            .iter()
            .fold(RuleTable::builder(), |builder, parts| {
                builder.rule(parts.rule())
            })
            .inline_assets(&inline_assets)
            .inline_limits(&case.inline_limits)
            .limits(&limits)
            .try_build()
            .expect("the parts build a table");
        let rows: Vec<[u8; 32]> = case.rules.iter().map(|row| bytes(row)).collect();
        let stored = TableParts {
            rows: &rows,
            inline_assets: &inline_assets,
            inline_limits: &case.inline_limits,
            limits: &limits,
        }
        .encode()
        .expect("the rows fit the table");
        assert_eq!(built.encode(), stored, "{}", case.name);
        let sources = case.source_map();
        assert_eq!(
            case.fields,
            stored.fields(&sources).map(hex::encode),
            "{}",
            case.name
        );
        assert_eq!(
            case.policy_hash,
            hex::encode(stored.hash(&sources).expect("policy hash")),
            "{}",
            case.name
        );
        let decoded = stored.decode().expect("the rows decode");
        assert_eq!(decoded, built, "{}", case.name);
        let parts: Vec<RuleParts> = decoded.rules().iter().map(RuleParts::new).collect();
        assert_eq!(parts, case.rule_parts, "{}", case.name);
    }
}

#[test]
#[ignore = "rewrites test-vectors/ring-policy-table.json"]
fn write_ring_policy_table_vector() {
    let json = serde_json::to_string_pretty(&compute_vectors()).expect("json");
    std::fs::write(VECTORS, json + "\n").expect("write vector file");
}
