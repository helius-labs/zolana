use crate::{CircuitError, Field, hash_bytes, poseidon, require_eq};

pub const SOLANA_OWNER_TAG: u8 = 0x53;

#[xark::input]
pub struct SigningPubkey {
    tag: u8,
    bytes: [u8; 32],
}

impl SigningPubkey {
    pub fn new(tag: u8, bytes: [u8; 32]) -> Self { Self { tag, bytes } }
    pub fn tag(&self) -> u8 { self.tag }
    pub fn bytes(&self) -> &[u8; 32] { &self.bytes }
    pub fn identity(&self) -> Result<Field, CircuitError> {
        let mut tagged = [0u8; 33];
        tagged[0] = self.tag;
        tagged[1..].copy_from_slice(&self.bytes);
        hash_bytes(&tagged)
    }
}

impl Default for SigningPubkey {
    fn default() -> Self { Self { tag: SOLANA_OWNER_TAG, bytes: [0; 32] } }
}

#[xark::input]
pub struct UtxoOwner {
    key: SigningPubkey,
    nullifier_pk: Field,
}

impl UtxoOwner {
    pub fn new(key: SigningPubkey, nullifier_pk: Field) -> Self { Self { key, nullifier_pk } }
    pub fn key(&self) -> &SigningPubkey { &self.key }
    pub fn nullifier_pk(&self) -> Field { self.nullifier_pk }
    pub fn hash(&self) -> Result<Field, CircuitError> {
        require_eq(self.key.tag, SOLANA_OWNER_TAG);
        poseidon(&[self.key.identity()?, self.nullifier_pk])
    }
    #[cfg(not(xark))]
    pub fn from_preimage(tag: u8, key: &[u8; 32], nullifier_pk: &[u8; 32]) -> Result<Self, CircuitError> {
        if tag != SOLANA_OWNER_TAG { return Err(crate::CircuitErrorKind::InvalidInput("owner tag is not S").into()); }
        Ok(Self::new(SigningPubkey::new(tag, *key), crate::from_bytes(nullifier_pk)?))
    }
    #[cfg(not(xark))]
    pub fn preimage(&self) -> (u8, [u8; 32], [u8; 32]) { (self.key.tag, self.key.bytes, crate::to_bytes(&self.nullifier_pk)) }
}

impl Default for UtxoOwner {
    fn default() -> Self { Self { key: SigningPubkey::default(), nullifier_pk: Field::zero() } }
}
impl PartialEq for UtxoOwner {
    fn eq(&self, other: &Self) -> bool { self.key.tag == other.key.tag && self.key.bytes == other.key.bytes && self.nullifier_pk == other.nullifier_pk }
}
impl Eq for UtxoOwner {}

#[xark::input]
pub struct ShieldedAddress {
    owner: UtxoOwner,
    viewing_pubkey: [u8; 33],
}

impl ShieldedAddress {
    pub fn new(owner: UtxoOwner, viewing_pubkey: [u8; 33]) -> Self { Self { owner, viewing_pubkey } }
    pub fn owner(&self) -> &UtxoOwner { &self.owner }
    pub fn viewing_pubkey(&self) -> &[u8; 33] { &self.viewing_pubkey }
    pub fn hash(&self) -> Result<Field, CircuitError> { poseidon(&[self.owner.hash()?, hash_bytes(&self.viewing_pubkey)?]) }
}
impl Default for ShieldedAddress {
    fn default() -> Self { Self { owner: UtxoOwner::default(), viewing_pubkey: [0; 33] } }
}
impl core::ops::Deref for ShieldedAddress {
    type Target = UtxoOwner;
    fn deref(&self) -> &Self::Target { &self.owner }
}

impl borsh::BorshSerialize for UtxoOwner {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        #[cfg(not(xark))]
        {
            let (tag, key, nullifier_pk) = self.preimage();
            borsh::BorshSerialize::serialize(&tag, writer)?;
            borsh::BorshSerialize::serialize(&key, writer)?;
            borsh::BorshSerialize::serialize(&nullifier_pk, writer)
        }
        #[cfg(xark)]
        { let _ = writer; panic!("owner serialization requires native execution") }
    }
}
impl borsh::BorshDeserialize for UtxoOwner {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        #[cfg(not(xark))]
        {
            let tag = u8::deserialize_reader(reader)?;
            let key = <[u8; 32]>::deserialize_reader(reader)?;
            let nullifier_pk = <[u8; 32]>::deserialize_reader(reader)?;
            Self::from_preimage(tag, &key, &nullifier_pk).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        }
        #[cfg(xark)]
        { let _ = reader; panic!("owner deserialization requires native execution") }
    }
}
