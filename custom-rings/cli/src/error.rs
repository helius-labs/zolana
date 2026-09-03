use thiserror::Error;

use crate::{
    authority::AuthorityError, config::ConfigError, deploy::DeployError, init::InitError,
    list::ListError, localnet::LocalnetError, new::NewError, pipeline::PipelineError,
    policy::PolicyCommandError, probe::ProbeError, reader::ReaderError,
    ring_rpc::RingRpcClientError, tool::ToolError, transact::TransactError,
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
    RingRpc(Box<RingRpcClientError>),
    #[error(transparent)]
    Authority(Box<AuthorityError>),
    #[error(transparent)]
    Reader(Box<ReaderError>),
    #[error(transparent)]
    List(Box<ListError>),
    #[error(transparent)]
    Policy(Box<PolicyCommandError>),
}

macro_rules! boxed_from {
    ($($variant:ident($error:ty)),* $(,)?) => {
        $(
            impl From<$error> for CliError {
                fn from(error: $error) -> Self {
                    Self::$variant(Box::new(error))
                }
            }
        )*
    };
}

boxed_from!(
    New(NewError),
    Probe(ProbeError),
    Pipeline(PipelineError),
    Localnet(LocalnetError),
    KeyFile(KeyFileError),
    Tool(ToolError),
    Deploy(DeployError),
    Init(InitError),
    Transact(TransactError),
    RingRpc(RingRpcClientError),
    Authority(AuthorityError),
    Reader(ReaderError),
    List(ListError),
    Policy(PolicyCommandError),
);

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
    crate::catalogue::CatalogueError,
    crate::catalogue::CuratorError,
    crate::deploy::DeployError,
    crate::fund::FundError,
    crate::status::StatusError,
    crate::transact::TransactError,
);
