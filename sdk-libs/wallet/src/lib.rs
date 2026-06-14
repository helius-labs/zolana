use solana_address::Address;
use solana_instruction::Instruction;
use zolana_client::testing::InMemoryPrivacyProvider;
use zolana_client::{
    ClientError, CreatePrivateWalletInput, DecryptionMode, GetDepositInstructionInput,
    GetPrivateTransactionsInput, HeliusPrivacyInterface, PrivacyClient, PrivateTokenBalances,
    PrivateTransaction, PrivateWallet, PrivateWalletId, SendPrivateTransferInput,
    SendPrivateTransferResult, SetDecryptionModeInput, SyncReport,
};
use zolana_keypair::ShieldedKeypair;
use zolana_transaction::test_wallet::TestWallet;

pub type Result<T> = std::result::Result<T, ClientError>;

#[derive(Clone, Default)]
pub struct ZolanaWalletEnvironment {
    provider: InMemoryPrivacyProvider,
}

impl ZolanaWalletEnvironment {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn native_client(&self, owner: Address) -> Result<PrivacyClient> {
        Ok(PrivacyClient::new_with_test_provider(
            owner,
            TestWallet::new(ShieldedKeypair::new()?)?,
            self.provider.clone(),
        ))
    }

    pub fn test_client(&self, owner: Address, keypair: ShieldedKeypair) -> Result<PrivacyClient> {
        PrivacyClient::new_for_tests(owner, keypair, self.provider.clone())
    }

    pub fn client_with_host(
        &self,
        owner: Address,
        host: impl HeliusPrivacyInterface + 'static,
    ) -> PrivacyClient {
        PrivacyClient::new_with_test_provider(owner, host, self.provider.clone())
    }
}

pub struct ZolanaWallet {
    owner: Address,
    client: PrivacyClient,
    private_wallet_id: Option<PrivateWalletId>,
}

impl ZolanaWallet {
    pub fn new(name: &str, environment: ZolanaWalletEnvironment) -> Result<Self> {
        Self::with_owner(owner_from_name(name), environment)
    }

    pub fn with_owner(owner: Address, environment: ZolanaWalletEnvironment) -> Result<Self> {
        let client = environment.native_client(owner)?;
        Self::from_client(owner, client)
    }

    pub fn with_test_keypair(
        owner: Address,
        keypair: ShieldedKeypair,
        environment: ZolanaWalletEnvironment,
    ) -> Result<Self> {
        let client = environment.test_client(owner, keypair)?;
        Self::from_client(owner, client)
    }

    pub fn from_client(owner: Address, client: PrivacyClient) -> Result<Self> {
        Ok(Self {
            owner,
            client,
            private_wallet_id: None,
        })
    }

    pub fn owner(&self) -> Address {
        self.owner
    }

    pub fn private_wallet_id(&self) -> Result<PrivateWalletId> {
        self.private_wallet_id
            .ok_or(ClientError::PrivateWalletNotFound)
    }

    pub async fn create_private_wallet(&mut self) -> Result<PrivateWallet> {
        let wallet = self
            .client
            .create_private_wallet(CreatePrivateWalletInput {
                inbox: self.owner,
                label: Some("Private Wallet".to_string()),
                decryption_mode: DecryptionMode::Local,
            })
            .await?;
        self.private_wallet_id = Some(wallet.id);
        Ok(wallet)
    }

    pub async fn set_decryption_mode(&mut self, mode: DecryptionMode) -> Result<PrivateWallet> {
        self.client
            .set_decryption_mode(SetDecryptionModeInput {
                private_wallet_id: self.private_wallet_id()?,
                mode,
            })
            .await
    }

    pub async fn sync_private_wallet(&mut self) -> Result<SyncReport> {
        self.client
            .sync_private_wallet(self.private_wallet_id()?)
            .await
    }

    pub async fn get_private_token_balances(&self) -> Result<PrivateTokenBalances> {
        self.client
            .get_private_token_balances(self.private_wallet_id()?)
            .await
    }

    pub async fn private_balance(&self, mint: Address) -> Result<u64> {
        Ok(self
            .get_private_token_balances()
            .await?
            .balances
            .into_iter()
            .find_map(|balance| (balance.mint == mint).then_some(balance.amount))
            .unwrap_or(0))
    }

    pub async fn get_private_transactions(&self, limit: usize) -> Result<Vec<PrivateTransaction>> {
        self.client
            .get_private_transactions(
                self.private_wallet_id()?,
                GetPrivateTransactionsInput { limit },
            )
            .await
    }

    pub async fn get_deposit_instruction(
        &self,
        source_token_account: Address,
        mint: Address,
        decimals: u8,
        amount: u64,
    ) -> Result<Instruction> {
        self.client
            .get_deposit_instruction(GetDepositInstructionInput {
                private_wallet_id: self.private_wallet_id()?,
                owner: self.owner,
                source_token_account,
                mint,
                decimals,
                amount,
            })
            .await
    }

    pub async fn send_private_transfer(
        &mut self,
        recipient: Address,
        mint: Address,
        amount: u64,
    ) -> Result<SendPrivateTransferResult> {
        self.client
            .send_private_transfer(SendPrivateTransferInput {
                private_wallet_id: self.private_wallet_id()?,
                recipient,
                mint,
                amount,
            })
            .await
    }

    pub async fn mock_airdrop(&mut self, mint: Address, amount: u64) -> Result<String> {
        self.client
            .mock_airdrop(self.private_wallet_id()?, mint, amount)
            .await
    }
}

fn owner_from_name(name: &str) -> Address {
    let mut bytes = [0u8; 32];
    bytes[0] = 0xA5;
    for (i, byte) in name.as_bytes().iter().take(31).enumerate() {
        bytes[i + 1] = *byte;
    }
    Address::new_from_array(bytes)
}
