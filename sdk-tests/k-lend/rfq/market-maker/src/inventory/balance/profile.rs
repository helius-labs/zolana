#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InventoryProfile {
    pub large: Vec<u64>,
    pub small: usize,
    pub min_utxo_value: u64,
}

impl InventoryProfile {
    pub fn equal(utxos: usize, min_utxo_value: u64) -> Self {
        Self {
            large: Vec::new(),
            small: utxos,
            min_utxo_value,
        }
    }

    pub fn count(&self) -> usize {
        self.large.len() + self.small.max(1)
    }

    pub fn targets(&self, balance: u64) -> Vec<u64> {
        if balance == 0 {
            return Vec::new();
        }
        let min = self.min_utxo_value.max(1);
        let mut targets = Vec::with_capacity(self.count());
        let mut rest = balance;
        for divisor in &self.large {
            let amount = balance / (*divisor).max(1);
            if amount >= min && amount < rest {
                targets.push(amount);
                rest -= amount;
            }
        }
        let by_value = usize::try_from(rest / min).unwrap_or(usize::MAX);
        let small = self.small.min(by_value).max(1);
        targets.extend(equal_parts(rest, small));
        targets.sort_by_key(|amount| std::cmp::Reverse(*amount));
        targets
    }

    pub fn missing(&self, balance: u64, utxos: &[u64]) -> Vec<u64> {
        let targets = self.targets(balance);
        unmatched(&targets, &match_utxos(&targets, utxos))
    }

    pub fn surplus_utxos(&self, balance: u64, utxos: &[u64]) -> usize {
        let targets = self.targets(balance);
        match_utxos(&targets, utxos)
            .utxos
            .iter()
            .filter(|matched| matched.is_none())
            .count()
    }

    pub fn parts(&self, value: u64, others: &[u64], max_parts: usize) -> Vec<u64> {
        let balance = others.iter().sum::<u64>().saturating_add(value);
        self.fill(value, self.missing(balance, others), max_parts)
    }

    pub fn split(&self, utxos: &[u64], max_parts: usize) -> Option<(usize, Vec<u64>)> {
        let targets = self.targets(utxos.iter().sum());
        let matching = match_utxos(&targets, utxos);
        let (index, amount, own) = utxos
            .iter()
            .zip(&matching.utxos)
            .enumerate()
            .map(|(index, (amount, target))| (index, *amount, target.unwrap_or(0)))
            .filter(|(_, amount, own)| amount > own)
            .max_by_key(|(_, amount, own)| amount - own)?;
        let wanted = (own > 0)
            .then_some(own)
            .into_iter()
            .chain(unmatched(&targets, &matching))
            .collect();
        let parts = self.fill(amount, wanted, max_parts);
        (parts.len() >= 2).then_some((index, parts))
    }

    fn fill(&self, value: u64, wanted: Vec<u64>, max_parts: usize) -> Vec<u64> {
        if value == 0 {
            return Vec::new();
        }
        let mut parts = Vec::new();
        let mut rest = value;
        for target in wanted {
            if parts.len() + 1 >= max_parts.max(1) {
                break;
            }
            if target <= rest {
                parts.push(target);
                rest -= target;
            }
        }
        match parts.last_mut() {
            Some(last) if rest < self.min_utxo_value => *last += rest,
            _ if rest > 0 => parts.push(rest),
            _ => {}
        }
        parts
    }
}

struct Matching {
    targets: Vec<bool>,
    utxos: Vec<Option<u64>>,
}

fn unmatched(targets: &[u64], matching: &Matching) -> Vec<u64> {
    let mut missing: Vec<u64> = targets
        .iter()
        .zip(&matching.targets)
        .filter(|(_, matched)| !**matched)
        .map(|(target, _)| *target)
        .collect();
    missing.sort_by_key(|amount| std::cmp::Reverse(*amount));
    missing
}

fn match_utxos(targets: &[u64], utxos: &[u64]) -> Matching {
    let mut pairs: Vec<(f64, usize, usize)> = targets
        .iter()
        .enumerate()
        .flat_map(|(target_index, target)| {
            utxos
                .iter()
                .enumerate()
                .map(move |(utxo_index, utxo)| (distance(*target, *utxo), target_index, utxo_index))
        })
        .collect();
    pairs.sort_by(|left, right| left.0.total_cmp(&right.0));
    let mut matching = Matching {
        targets: vec![false; targets.len()],
        utxos: vec![None; utxos.len()],
    };
    for (_, target_index, utxo_index) in pairs {
        let free = matching.targets.get(target_index) == Some(&false)
            && matching.utxos.get(utxo_index) == Some(&None);
        if !free {
            continue;
        }
        if let (Some(target_matched), Some(utxo), Some(target)) = (
            matching.targets.get_mut(target_index),
            matching.utxos.get_mut(utxo_index),
            targets.get(target_index),
        ) {
            *target_matched = true;
            *utxo = Some(*target);
        }
    }
    matching
}

fn distance(target: u64, utxo: u64) -> f64 {
    let target = (target.max(1) as f64).ln();
    let utxo = (utxo.max(1) as f64).ln();
    (target - utxo).abs()
}

pub fn equal_parts(amount: u64, parts: usize) -> Vec<u64> {
    let count = u64::try_from(parts.max(1)).unwrap_or(1).min(amount.max(1));
    let part = amount / count;
    (0..count)
        .map(|index| {
            if index + 1 == count {
                amount - part * (count - 1)
            } else {
                part
            }
        })
        .collect()
}
