use thiserror::Error;

use crate::{
    authority::AuthorityError, build_program::BuildError, config::ConfigError, deploy::DeployError,
    generate::GenerateError, init::InitError, keys::AuditorKeyError, pipeline::PipelineError,
    probe::ProbeError, reader::ReaderError, repo::RepoError, ring_rpc::RpcCheckError,
    transact::TransactError,
};

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
    AuditorKey(Box<AuditorKeyError>),
    #[error(transparent)]
    Repo(Box<RepoError>),
    #[error(transparent)]
    Deploy(Box<DeployError>),
    #[error(transparent)]
    Init(Box<InitError>),
    #[error(transparent)]
    Transact(Box<TransactError>),
    #[error(transparent)]
    RpcCheck(Box<RpcCheckError>),
    #[error(transparent)]
    Authority(Box<AuthorityError>),
    #[error(transparent)]
    Reader(Box<ReaderError>),
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
    AuditorKey(AuditorKeyError),
    Repo(RepoError),
    Deploy(DeployError),
    Init(InitError),
    Transact(TransactError),
    RpcCheck(RpcCheckError),
    Authority(AuthorityError),
    Reader(ReaderError),
);
