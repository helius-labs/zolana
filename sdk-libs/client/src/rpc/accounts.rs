/// Filters sent with a `getProgramAccounts` request. A service that cannot
/// apply them or honor the minimum context slot must fail rather than silently
/// perform an unfiltered or stale read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProgramAccountsFilter {
    data_size: usize,
    memcmp: Vec<MemcmpFilter>,
    min_context_slot: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MemcmpFilter {
    offset: usize,
    bytes: Vec<u8>,
}

impl ProgramAccountsFilter {
    pub fn new(data_size: usize) -> Self {
        Self {
            data_size,
            memcmp: Vec::new(),
            min_context_slot: None,
        }
    }

    #[must_use]
    pub fn with_memcmp(mut self, offset: usize, bytes: impl Into<Vec<u8>>) -> Self {
        self.memcmp.push(MemcmpFilter {
            offset,
            bytes: bytes.into(),
        });
        self
    }

    /// Fail the request if the RPC node has not reached `slot`.
    #[must_use]
    pub fn with_min_context_slot(mut self, slot: u64) -> Self {
        self.min_context_slot = Some(slot);
        self
    }

    pub fn min_context_slot(&self) -> Option<u64> {
        self.min_context_slot
    }

    pub fn matches(&self, data: &[u8]) -> bool {
        data.len() == self.data_size
            && self.memcmp.iter().all(|memcmp| {
                data.get(memcmp.offset..)
                    .is_some_and(|window| window.starts_with(&memcmp.bytes))
            })
    }

    pub fn data_size(&self) -> usize {
        self.data_size
    }

    /// The byte windows a custom RPC transport must include in its query.
    pub fn memcmp_filters(&self) -> impl Iterator<Item = (usize, &[u8])> {
        self.memcmp
            .iter()
            .map(|filter| (filter.offset, filter.bytes.as_slice()))
    }
}
