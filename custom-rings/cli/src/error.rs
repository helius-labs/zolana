use thiserror::Error;

use crate::{
    authority::AuthorityError, config::ConfigError, cosigner::CoSignerError,
    delegate::DelegateError, deploy::DeployError, init::InitError, key::KeyError, list::ListError,
    localnet::LocalnetError, merge::MergeError, new::NewError, pipeline::PipelineError,
    policy::PolicyCommandError, probe::ProbeError, reader::ReaderError,
    ring_rpc::RingRpcClientError, spend::SpendError, tool::ToolError, transact::TransactError,
    window::WindowError,
};
use zolana_ring_rpc::KeyFileError;

#[derive(Debug, Error)]
pub enum CliError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    New(Box<NewError>),
    #[error(transparent)]
    Probe(Box<ProbeError>),
    #[error(transparent)]
    Pipeline(Box<PipelineError>),
    #[error(transparent)]
    Localnet(Box<LocalnetError>),
    #[error(transparent)]
    KeyFile(Box<KeyFileError>),
    #[error(transparent)]
    Tool(Box<ToolError>),
    #[error(transparent)]
    Deploy(Box<DeployError>),
    #[error(transparent)]
    Init(Box<InitError>),
    #[error(transparent)]
    Transact(Box<TransactError>),
    #[error(transparent)]
    Merge(Box<MergeError>),
    #[error(transparent)]
    RingRpc(Box<RingRpcClientError>),
    #[error(transparent)]
    Authority(Box<AuthorityError>),
    #[error(transparent)]
    Reader(Box<ReaderError>),
    #[error(transparent)]
    CoSigner(Box<CoSignerError>),
    #[error(transparent)]
    Window(Box<WindowError>),
    #[error(transparent)]
    Delegate(Box<DelegateError>),
    #[error(transparent)]
    Spend(Box<SpendError>),
    #[error(transparent)]
    Key(Box<KeyError>),
    #[error(transparent)]
    List(Box<ListError>),
    #[error(transparent)]
    Policy(Box<PolicyCommandError>),
}

macro_rules! boxed_from {
    ($target:ty { $($variant:ident($error:ty)),* $(,)? }) => {
        $(
            impl From<$error> for $target {
                fn from(error: $error) -> Self {
                    Self::$variant(Box::new(error))
                }
            }
        )*
    };
}

pub(crate) use boxed_from;

boxed_from!(CliError {
    New(NewError),
    Probe(ProbeError),
    Pipeline(PipelineError),
    Localnet(LocalnetError),
    KeyFile(KeyFileError),
    Tool(ToolError),
    Deploy(DeployError),
    Init(InitError),
    Transact(TransactError),
    Merge(MergeError),
    RingRpc(RingRpcClientError),
    Authority(AuthorityError),
    Reader(ReaderError),
    CoSigner(CoSignerError),
    Window(WindowError),
    Delegate(DelegateError),
    Spend(SpendError),
    Key(KeyError),
    List(ListError),
    Policy(PolicyCommandError),
});

/// One `Client` variant per module, boxed for enum size.
macro_rules! client_from {
    ($($error:ty),* $(,)?) => {$(
        impl From<zolana_client::ClientError> for $error {
            fn from(error: zolana_client::ClientError) -> Self {
                Self::Client(Box::new(error))
            }
        }
    )*};
}

client_from!(
    crate::ContextError,
    crate::assets::AssetError,
    crate::catalogue::CatalogueError,
    crate::catalogue::CuratorError,
    crate::cosigner::CoSignerError,
    crate::deploy::DeployError,
    crate::fund::FundError,
    crate::key::KeyError,
    crate::status::StatusError,
    crate::transact::TransactError,
    crate::merge::MergeError,
    crate::window::WindowError,
);
