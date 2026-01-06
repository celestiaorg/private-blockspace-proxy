use core::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Error, Serialize, Deserialize)]
pub enum PbsRunnerError {
    #[error("Service: {0}")]
    InternalError(String),

    #[error("ZK Prover: {0}")]
    ZkClientError(String),

    #[error("Data Availability Node: {0}")]
    DaClientError(String),

    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),
}

// This removes a layer of escape chars for json formatting
impl fmt::Debug for PbsRunnerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PbsRunnerError::InternalError(s) => write!(f, "InternalError({s})"),
            PbsRunnerError::ZkClientError(s) => write!(f, "ZkClientError({s})"),
            PbsRunnerError::DaClientError(s) => write!(f, "DaClientError({s})"),
            PbsRunnerError::InvalidParameter(s) => write!(f, "InvalidParameter({s})"),
        }
    }
}
