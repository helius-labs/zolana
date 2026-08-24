use thiserror::Error;

use crate::{
    authority::AuthorityError, config::ConfigError, deploy::DeployError, init::InitError,
    reader::ReaderError, ring_rpc::RpcCheckError, transact::TransactError,
};

#[derive(Debug, Error)]
pub enum CliError {
    #[error(transparent)]
    Config(#[from] ConfigError),
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
    Deploy(DeployError),
    Init(InitError),
    Transact(TransactError),
    RpcCheck(RpcCheckError),
    Authority(AuthorityError),
    Reader(ReaderError),
);
