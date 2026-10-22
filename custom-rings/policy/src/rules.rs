//! The list rules one transfer meets before proving, mirror
//! `prover/server/custom_rings/circuits/policy/rules.go` and `subjects.go`.

use core::fmt;

use thiserror::Error;

use crate::{Guard, ListSet, Rule, RuleSource, RuleTable, SourceMap, Subject};

/// A member's record `lists` in each registry, zero for an absent member.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecordLists {
    pub own: u64,
    /// Read only for a list a curator serves.
    pub curator: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutputSubjects {
    /// The owner identity, zero carries no owner obligation.
    pub owner: [u8; 32],
    /// `Member::asset` of the mint.
    pub asset: [u8; 32],
    pub amount: u64,
    pub owner_lists: RecordLists,
    pub asset_lists: RecordLists,
}

#[derive(Clone, Copy, Debug)]
pub struct TransferSubjects<'a> {
    pub sender: RecordLists,
    /// The UTXO outputs in slot order, dummies and compact padding left out.
    pub outputs: &'a [OutputSubjects],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferSubject {
    Sender,
    /// The owner of output `n`.
    Owner(usize),
    /// The asset of output `n`.
    Asset(usize),
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum RuleRefusal {
    #[error("rule {rule} refuses {subject}")]
    Lists {
        rule: usize,
        subject: TransferSubject,
    },
    #[error("rule {rule} has no asset limit for the asset of output {output}")]
    NoAssetLimit { rule: usize, output: usize },
    #[error("rule {rule} sums each owner over one asset, output {output} carries another")]
    MixedAssets { rule: usize, output: usize },
}

impl RuleTable {
    /// The first refusal in the circuit's constraint order, caps, outflow and co-sign left out.
    pub fn admit(
        &self,
        sources: &SourceMap,
        transfer: &TransferSubjects<'_>,
    ) -> Result<(), RuleRefusal> {
        self.admit_one_asset(transfer.outputs)?;
        let foreign = foreign_lists(sources);
        for (index, rule) in self.rules().iter().enumerate() {
            let check = RuleCheck {
                table: self,
                outputs: transfer.outputs,
                foreign,
                index,
                rule,
            };
            match rule.subject {
                // No guard exempts the sender, with or without a spent input.
                Subject::Sender => check.listed(TransferSubject::Sender, transfer.sender)?,
                Subject::OutputOwner | Subject::Asset => {
                    (0..transfer.outputs.len()).try_for_each(|output| check.output(output))?
                }
                Subject::ExitDestination => {}
            }
        }
        Ok(())
    }

    /// A scalar guard on an owner rule sums an owner's outputs, all of one asset.
    fn admit_one_asset(&self, outputs: &[OutputSubjects]) -> Result<(), RuleRefusal> {
        let Some(rule) = self.rules().iter().position(|rule| {
            rule.subject == Subject::OutputOwner && matches!(rule.guard, Guard::AboveAmount(_))
        }) else {
            return Ok(());
        };
        let mixed = outputs.first().and_then(|first| {
            outputs
                .iter()
                .position(|output| output.asset != first.asset)
        });
        mixed.map_or(Ok(()), |output| {
            Err(RuleRefusal::MixedAssets { rule, output })
        })
    }

    /// The rows name distinct assets.
    fn asset_limit(&self, asset: &[u8; 32]) -> Option<u64> {
        self.inline_assets()
            .iter()
            .zip(self.inline_limits())
            .find_map(|(inline, limit)| (inline == asset).then_some(*limit))
    }
}

impl fmt::Display for TransferSubject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sender => f.write_str("the sender"),
            Self::Owner(output) => write!(f, "the owner of output {output}"),
            Self::Asset(output) => write!(f, "the asset of output {output}"),
        }
    }
}

impl RecordLists {
    /// List `i + 1` reads the curator record when a curator serves it, else the own record.
    fn on(self, foreign: ListSet) -> ListSet {
        let foreign = foreign.record_bits();
        ListSet::from_bits(((self.own & !foreign) | (self.curator & foreign)) as u8)
    }
}

struct RuleCheck<'a> {
    table: &'a RuleTable,
    outputs: &'a [OutputSubjects],
    foreign: ListSet,
    index: usize,
    rule: &'a Rule,
}

impl RuleCheck<'_> {
    fn output(&self, index: usize) -> Result<(), RuleRefusal> {
        let output = &self.outputs[index];
        let on_asset = self.rule.subject == Subject::Asset;
        if !on_asset && output.owner == [0; 32] {
            return Ok(());
        }
        let limit = self.table.asset_limit(&output.asset);
        if self.rule.guard == Guard::AboveAmountByAsset && limit.is_none() {
            return Err(RuleRefusal::NoAssetLimit {
                rule: self.index,
                output: index,
            });
        }
        let live_owner =
            |other: &OutputSubjects| other.owner != [0; 32] && other.owner == output.owner;
        let same_asset = |other: &OutputSubjects| other.asset == output.asset;
        let exempt = match self.rule.guard {
            Guard::Always => false,
            Guard::AboveAmount(threshold) if on_asset => {
                self.total(same_asset) <= u128::from(threshold)
            }
            Guard::AboveAmount(threshold) => self.total(live_owner) <= u128::from(threshold),
            Guard::AboveAmountByAsset => limit.is_some_and(|limit| {
                self.total(|other| live_owner(other) && same_asset(other)) <= u128::from(limit)
            }),
        };
        if exempt {
            return Ok(());
        }
        if on_asset {
            self.listed(TransferSubject::Asset(index), output.asset_lists)
        } else {
            self.listed(TransferSubject::Owner(index), output.owner_lists)
        }
    }

    fn listed(&self, subject: TransferSubject, records: RecordLists) -> Result<(), RuleRefusal> {
        if holds(self.rule, records.on(self.foreign)) {
            return Ok(());
        }
        Err(RuleRefusal::Lists {
            rule: self.index,
            subject,
        })
    }

    fn total(&self, grouped: impl Fn(&OutputSubjects) -> bool) -> u128 {
        self.outputs
            .iter()
            .filter(|other| grouped(other))
            .map(|other| u128::from(other.amount))
            .sum()
    }
}

/// On any list of the present set, or off any list of the absent set.
fn holds(rule: &Rule, on: ListSet) -> bool {
    let RuleSource::Lists { present, absent } = rule.source;
    present.intersects(on) || !absent.difference(on).is_empty()
}

fn foreign_lists(sources: &SourceMap) -> ListSet {
    let bits = sources
        .slots()
        .iter()
        .enumerate()
        .filter(|(_, slot)| slot.registry != [0; 32])
        .fold(0u8, |bits, (slot, _)| bits | 1 << slot);
    ListSet::from_bits(bits)
}
