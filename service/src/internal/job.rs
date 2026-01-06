use core::fmt;

use crate::PbsRunnerError;

use serde::{Deserialize, Serialize};
use sp1_sdk::SP1ProofWithPublicValues;

use crate::SuccNetJobId;

/// A job for the service, mapped to a...
/// TODO
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Job {
    pub anchor: Anchor,
    pub input: Input,
}

/// A (set of) input(s) for the zkVM
/// TODO: what should structure be?
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Input {
    pub data: Vec<u8>,
}

/// A commitment to the input, likely a hash or related fingerprint.
/// TODO: what should structure be?
#[derive(Serialize, Deserialize, Clone)]
pub struct Anchor {
    pub data: Vec<u8>,
}

impl AsRef<[u8]> for Anchor {
    fn as_ref(&self) -> &[u8] {
        self.data.as_slice()
    }
}

impl fmt::Debug for Anchor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let anchor_hex = bytes_to_hex(&self.data);
        f.debug_struct("Anchor")
            .field("data (hex)", &anchor_hex)
            .finish()
    }
}

/// Used as a [Job] state machine for the PBS service.
#[derive(Serialize, Deserialize)]
pub enum JobStatus {
    /// A ZK prover job had been started, awaiting completion
    LocalZkProofPending,
    /// A ZK prover job is being requested, gathering prover network ID
    RemoteZkProofRequesting,
    /// A ZK prover job has been requested, awaiting response
    RemoteZkProofPending(SuccNetJobId),
    /// A ZK proof is ready, and the [Job] is complete
    // For now we'll use the SP1ProofWithPublicValues as the proof
    // Ideally we only want the public values + whatever is needed to verify the proof
    // They don't seem to provide a type for that.
    ZkProofFinished(SP1ProofWithPublicValues),
    /// A wrapper for any [PbsRunnerError], with:
    /// - Option = None                        --> Permanent failure
    /// - Option = Some(\<retry-able status\>) --> Retry is possible, with a JobStatus state to retry with
    Failed(PbsRunnerError, Option<Box<JobStatus>>),
}

impl std::fmt::Debug for JobStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JobStatus::LocalZkProofPending => write!(f, "LocalZkProofPending"),
            JobStatus::RemoteZkProofRequesting => write!(f, "RemoteZkProofRequesting"),
            JobStatus::RemoteZkProofPending(_) => write!(f, "RemoteZkProofPending"),
            JobStatus::ZkProofFinished(_) => write!(f, "ZkProofFinished"),
            JobStatus::Failed(_, _) => write!(f, "Failed"),
        }
    }
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let digest_hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    digest_hex
}
