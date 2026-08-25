use thiserror::Error;

use crate::{
    authority::AuthorityError, build_program::BuildError, config::ConfigError, deploy::DeployError,
    generate::GenerateError, init::InitError, pipeline::PipelineError, probe::ProbeError,
    reader::ReaderError, record::RecordError, ring_rpc::RingRpcClientError, tool::ToolError,
    transact::TransactError,
};
use zolana_ring_rpc::KeyFileError;

#[derive(Debug, Error)]
pub enum CliError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Generate(Box<GenerateError>),
    #[error(transparent)]
    Build(Box<BuildError>),
    #[error(transparent)]
    Probe(Box<ProbeError>),
    #[error(transparent)]
    Pipeline(Box<PipelineError>),
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
    Record(Box<RecordError>),
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
    Generate(GenerateError),
    Build(BuildError),
    Probe(ProbeError),
    Pipeline(PipelineError),
    KeyFile(KeyFileError),
    Tool(ToolError),
    Deploy(DeployError),
    Init(InitError),
    Transact(TransactError),
    RingRpc(RingRpcClientError),
    Authority(AuthorityError),
    Reader(ReaderError),
    Record(RecordError),
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
    crate::deploy::DeployError,
    crate::fund::FundError,
    crate::status::StatusError,
    crate::transact::TransactError,
);
