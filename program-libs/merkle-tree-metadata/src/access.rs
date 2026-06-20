use bytemuck::{Pod, Zeroable};
use solana_address::Address as Pubkey;

#[repr(C)]
#[derive(Debug, PartialEq, Default, Pod, Zeroable, Clone, Copy)]
pub struct AccessMetadata {
    /// Owner of the Merkle tree.
    pub owner: Pubkey,
    /// Program owner of the Merkle tree. This will be used for program owned Merkle trees.
    pub program_owner: Pubkey,
    /// Optional privileged forester pubkey, can be set for custom Merkle trees
    /// without a network fee. Merkle trees without network fees are not
    /// forested by light foresters. The variable is not used in the account
    /// compression program but the registry program. The registry program
    /// implements access control to prevent contention during forester. The
    /// forester pubkey specified in this struct can bypass contention checks.
    pub forester: Pubkey,
}

impl borsh::BorshSerialize for AccessMetadata {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        crate::serialize_address(&self.owner, writer)?;
        crate::serialize_address(&self.program_owner, writer)?;
        crate::serialize_address(&self.forester, writer)
    }
}

impl borsh::BorshDeserialize for AccessMetadata {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        Ok(Self {
            owner: crate::deserialize_address(reader)?,
            program_owner: crate::deserialize_address(reader)?,
            forester: crate::deserialize_address(reader)?,
        })
    }
}

impl AccessMetadata {
    pub fn new(owner: Pubkey, program_owner: Option<Pubkey>, forester: Option<Pubkey>) -> Self {
        Self {
            owner,
            program_owner: program_owner.unwrap_or_default(),
            forester: forester.unwrap_or_default(),
        }
    }
}

#[test]
fn test_new() {
    let owner = Pubkey::new_unique();
    let program_owner = Pubkey::new_unique();
    let forester = Pubkey::new_unique();
    let access_metadata = AccessMetadata::new(owner, Some(program_owner), Some(forester));
    assert_eq!(access_metadata.owner, owner);
    assert_eq!(access_metadata.program_owner, program_owner);
    assert_eq!(access_metadata.forester, forester);

    // With no program owner and forester
    let access_metadata = AccessMetadata::new(owner, None, None);
    assert_eq!(access_metadata.owner, owner);
    assert_eq!(access_metadata.program_owner, Pubkey::default());
    assert_eq!(access_metadata.forester, Pubkey::default());
}
