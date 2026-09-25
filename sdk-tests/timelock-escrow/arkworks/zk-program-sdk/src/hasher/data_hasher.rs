use zolana_hasher::{Hasher, HasherError};

pub trait DataHasher {
    fn hash<H: Hasher>(&self) -> Result<[u8; 32], HasherError>;
}
