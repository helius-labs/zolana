#[derive(Debug, Default, Clone, Copy, Eq, PartialEq)]
pub struct RawIndexedElement<I>
where
    I: Clone,
{
    pub value: [u8; 32],
    pub next_index: I,
    pub next_value: [u8; 32],
    pub index: I,
}
