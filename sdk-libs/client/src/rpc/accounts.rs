/// Filters sent with a `getProgramAccounts` request. A service that cannot
/// apply them must fail rather than silently perform an unfiltered read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProgramAccountsFilter {
    data_size: usize,
    memcmp: Vec<MemcmpFilter>,
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
