use crate::{Job, JobStatus, PbsRunnerError, SP1ProofSetup, SuccNetProgramId, internal::util};

use hex::FromHex;
use log::{debug, error, info, warn};
use sha2::Digest;
use sled::{Transactional, Tree as SledTree};
use sp1_sdk::{
    EnvProver as SP1EnvProver, NetworkProver as SP1NetworkProver, Prover, SP1ProofWithPublicValues,
    SP1Stdin,
    network::{Error as SP1NetworkError, FulfillmentStrategy},
};
use std::{sync::Arc, time::Duration};
use tokio::sync::{OnceCell, mpsc};

/// Hardcoded ELF binary for the crate `program-keccak-inclusion`
/// For reproducible builds, you need `cargo prove --docker`
#[cfg(feature = "reproducible-elf")]
pub const CHACHA_ELF: &[u8] = include_bytes!(
    "../../../target/elf-compilation/docker/riscv32im-succinct-zkvm-elf/release/chacha-program"
);

#[cfg(not(feature = "reproducible-elf"))]
pub const CHACHA_ELF: &[u8] = include_bytes!(
    "../../../target/elf-compilation/riscv32im-succinct-zkvm-elf/release/chacha-program"
);

/// Hardcoded ID for the crate `program-keccak-inclusion`
static CHACHA_ID: OnceCell<SuccNetProgramId> = OnceCell::const_new();

/// Given a hard coded ELF, get it's ID
/// TODO: generalize
pub async fn get_program_id() -> SuccNetProgramId {
    *CHACHA_ID
        .get_or_init(|| async {
            debug!("Building Program ID");
            sha2::Sha256::digest(CHACHA_ELF).into()
        })
        .await
}

static CHACHA_SETUP: OnceCell<Arc<SP1ProofSetup>> = OnceCell::const_new();

/// Configuration for the PBS Runner
pub struct PbsRunnerConfig {
    /// Timeout in seconds for onchain auction to win a prover to process
    pub zk_proof_auction_timeout_remote: Duration,
    /// Timeout in seconds for prover network proof generation
    pub zk_proof_gen_timeout_remote: Duration,
}

/// The main service runner.
pub struct PbsRunner {
    pub config: PbsRunnerConfig,
    pub config_db: SledTree,
    pub queue_db: SledTree,
    pub finished_db: SledTree,
    pub job_sender: mpsc::UnboundedSender<Option<Job>>,
    zk_client_handle_local: OnceCell<Arc<SP1EnvProver>>,
    zk_client_handle_remote: OnceCell<Arc<SP1NetworkProver>>,
}

impl PbsRunner {
    /// As we need a [OnceCell] internal to this struct, you must use `new`
    /// to correctly construct it.
    pub fn new(
        config: PbsRunnerConfig,
        zk_client_handle_local: OnceCell<Arc<SP1EnvProver>>,
        zk_client_handle_remote: OnceCell<Arc<SP1NetworkProver>>,
        config_db: SledTree,
        queue_db: SledTree,
        finished_db: SledTree,
        job_sender: mpsc::UnboundedSender<Option<Job>>,
    ) -> Self {
        PbsRunner {
            config,
            zk_client_handle_local,
            zk_client_handle_remote,
            config_db,
            queue_db,
            finished_db,
            job_sender,
        }
    }

    /// The main method: sending a [Job] to this PBS Runner.
    /// If Job is finished, returns Ok(Some(Proof)),
    /// or Ok(None) if we don't have one (yet, likely pending)
    pub async fn get_verifiable_encryption(
        &self,
        job: Job,
    ) -> Result<Option<SP1ProofWithPublicValues>, PbsRunnerError> {
        let job_key = bincode::serialize(&job.anchor)
            .map_err(|e| PbsRunnerError::InternalError(e.to_string()))?;
        info!("0x{} - Received request", hex::encode(&job_key));

        // Check DB for finished jobs
        if let Some(proof_data) = self
            .finished_db
            .get(&job_key)
            .map_err(|e| PbsRunnerError::InternalError(e.to_string()))?
        {
            let job_status: JobStatus = bincode::deserialize(&proof_data)
                .map_err(|e| PbsRunnerError::InternalError(e.to_string()))?;

            match job_status {
                JobStatus::ZkProofFinished(proof) => {
                    debug!("Job finished, returning proof from DB");
                    return Ok(Some(proof));
                }
                JobStatus::Failed(error, maybe_status) => {
                    match maybe_status {
                        None => {
                            warn!("Job is PERMANENT FAILURE, returning status");
                            return Err(PbsRunnerError::InternalError(format!("{error:?}")));
                        }
                        Some(retry_status) => {
                            warn!("Job is Retry-able Failure, returning status & retrying");
                            // We retry errors on each call
                            // for a specific [Job] by sending to the queue
                            match self.send_job_with_new_status(job_key, *retry_status, job) {
                                Ok(_) => {
                                    return Err(PbsRunnerError::InternalError(format!(
                                        "Retrying! Previous error: {error:?}"
                                    )));
                                }
                                Err(e) => {
                                    return Err(PbsRunnerError::InternalError(format!(
                                        "PLEASE REPORT! Internal error, cannot retry: {e:?}"
                                    )));
                                }
                            }
                        }
                    }
                }
                _ => {
                    let e = "PLEASE REPORT! Finished DB is in invalid state";
                    error!("{e}");
                    return Err(PbsRunnerError::InternalError(e.to_string()));
                }
            }
        }

        // Check DB for pending jobs
        if let Some(queue_data) = self
            .queue_db
            .get(&job_key)
            .map_err(|e| PbsRunnerError::InternalError(e.to_string()))?
        {
            debug!("Job in pending queue");
            let job_status: JobStatus = bincode::deserialize(&queue_data)
                .map_err(|e| PbsRunnerError::InternalError(e.to_string()))?;
            match job_status {
                JobStatus::LocalZkProofPending => return Ok(None),
                JobStatus::RemoteZkProofRequesting => return Ok(None),
                JobStatus::RemoteZkProofPending(_) => return Ok(None),
                _ => {
                    let e = format!(
                        "0x{} - Job queue is in invalid state",
                        hex::encode(&job_key)
                    );
                    error!("{e}");
                    return Err(PbsRunnerError::InternalError(e));
                }
            }
        }

        info!(
            "0x{} - New job sending to worker and adding to queue",
            hex::encode(&job_key)
        );

        let prover_type = std::env::var("SP1_PROVER").expect("Missing SP1_PROVER env var");
        // Match on the prover string to produce a JobStatus variant
        let initial_status = match prover_type.as_str() {
            "network" => JobStatus::RemoteZkProofRequesting,
            "cuda" | "cpu" | "mock" => JobStatus::LocalZkProofPending,
            unknown_str => {
                let e = format!("SP1_PROVER is unknown: {unknown_str}");
                error!("{e}");
                return Err(PbsRunnerError::InternalError(e));
            }
        };

        self.queue_db
            .insert(
                &job_key,
                bincode::serialize(&initial_status)
                    .map_err(|e| PbsRunnerError::InternalError(e.to_string()))?,
            )
            .map_err(|e| PbsRunnerError::InternalError(e.to_string()))?;

        self.job_sender
            .send(Some(job.clone()))
            .map_err(|e| PbsRunnerError::InternalError(e.to_string()))?;

        Ok(None)
    }

    ///A worker that receives [Job]s by a channel and drives them to completion.
    ///
    /// `Job`s are complete stepwise with a [JobStatus] that is recorded in a
    /// queue database, with work to progress each status to towards completion async.
    /// Once a step is completed, `JobStatus` is recorded into the queue database that
    /// recursively, driving to `Job` completion.
    ///
    /// When a successful or failed state is arrived at,
    /// the job is atomically removed from the queue and added to a results database.
    pub async fn job_worker(
        self: Arc<Self>,
        mut job_receiver: mpsc::UnboundedReceiver<Option<Job>>,
    ) {
        debug!("Job worker started");
        while let Some(Some(job)) = job_receiver.recv().await {
            let service = self.clone();
            tokio::spawn(async move {
                debug!("Worker received job");
                let _ = service.prove(job).await; //Don't return with "?", we run keep looping
            });
        }

        info!("Shutting down");
        let _ = self.queue_db.flush();
        let _ = self.finished_db.flush();
        info!("Cleanup complete");

        std::process::exit(0);
    }

    /// The main service task: produce a proof based on a [Job] requested.
    async fn prove(&self, job: Job) -> Result<(), PbsRunnerError> {
        let job_key = bincode::serialize(&job.anchor)
            .map_err(|e| PbsRunnerError::InternalError(e.to_string()))?;
        if let Some(queue_data) = self
            .queue_db
            .get(&job_key)
            .map_err(|e| PbsRunnerError::InternalError(e.to_string()))?
        {
            let mut job_status: JobStatus = bincode::deserialize(&queue_data)
                .map_err(|e| PbsRunnerError::InternalError(e.to_string()))?;
            debug!("Job worker processing with starting status: {job_status:?}");
            match job_status {
                JobStatus::RemoteZkProofRequesting => {
                    // TODO handle non-hardcoded ZK programs
                    match self
                        .zk_proof_remote(&get_program_id().await, &job, &job_key)
                        .await
                    {
                        Ok(zk_job_id) => {
                            job_status = JobStatus::RemoteZkProofPending(zk_job_id);
                            self.send_job_with_new_status(job_key, job_status, job)?;
                        }
                        Err(e) => {
                            error!("{job:?} failed to request a proof: {e}");
                            // NOTE: we internally finalize the job in `handle_zk_client_error`
                        }
                    };
                    debug!("ZK proof request sent");
                }
                JobStatus::RemoteZkProofPending(zk_request_id) => {
                    debug!("ZK request waiting");
                    match self.wait_for_zk_proof(&job, &job_key, zk_request_id).await {
                        Ok(zk_proof) => {
                            info!("🎉 {job:?} Finished!");
                            job_status = JobStatus::ZkProofFinished(zk_proof);
                            self.finalize_job(&job_key, job_status)?;
                        }
                        Err(e) => {
                            error!("{job:?} failed progressing RemoteZkProofPending: {e}");
                            // NOTE: we internally finalize the job in `handle_zk_client_error`
                        }
                    }
                    debug!("Remote ZK request fulfilled, result stored in DB");
                }
                JobStatus::LocalZkProofPending => {
                    // TODO handle non-hardcoded ZK programs
                    match self
                        .zk_proof_local(&get_program_id().await, &job, &job_key)
                        .await
                    {
                        Ok(zk_proof) => {
                            info!("0x{} - 🎉 Finished!", hex::encode(&job_key));
                            job_status = JobStatus::ZkProofFinished(zk_proof);
                            self.finalize_job(&job_key, job_status)?;
                        }
                        Err(e) => {
                            error!("{job:?} - Failed progressing LocalZkProofPending: {e}",);
                            // NOTE: we internally finalize the job in `handle_zk_client_error`
                        }
                    };
                    debug!("0x{} - ZKP stored in finalized DB", hex::encode(job_key));
                }
                _ => error!("Queue has INVALID status! Finished jobs stuck in queue!"),
            }
        };
        Ok(())
    }

    /// Given a SHA2 hash of a ZK program, get the require setup.
    /// The setup is a very heavy task and produces a large output (~200MB),
    /// fortunately it's identical per ZK program, so we store this in a DB to recall it.
    /// We load it and return a pointer to a single instance of this large setup object
    /// to read from for many concurrent [Job]s.
    pub async fn get_proof_setup_local(
        &self,
        zk_program_elf_sha2: &[u8; 32],
        zk_client_handle: Arc<SP1EnvProver>,
    ) -> Result<Arc<SP1ProofSetup>, PbsRunnerError> {
        debug!("Getting ZK program proof setup");
        let setup = CHACHA_SETUP
            .get_or_try_init(|| async {
                // Check DB for existing pre-computed setup
                let precomputed_proof_setup = self
                    .config_db
                    .get(zk_program_elf_sha2)
                    .map_err(|e| PbsRunnerError::InternalError(e.to_string()))?;

                let proof_setup = match precomputed_proof_setup { Some(precomputed) => {
                    bincode::deserialize(&precomputed)
                        .map_err(|e| PbsRunnerError::InternalError(e.to_string()))?
                } _ => {
                    info!(
                        "No ZK proof setup in DB for SHA2_256 = 0x{} -- generation & storing in config DB",
                        hex::encode(zk_program_elf_sha2)
                    );

                    let new_proof_setup: SP1ProofSetup = tokio::task::spawn_blocking(move || {
                        zk_client_handle.setup(CHACHA_ELF).into()
                    })
                    .await
                    .map_err(|e| PbsRunnerError::InternalError(e.to_string()))?;

                    self.config_db
                        .insert(
                        zk_program_elf_sha2,
                        bincode::serialize(&new_proof_setup)
                            .map_err(|e| PbsRunnerError::InternalError(e.to_string()))?,
                        )
                        .map_err(|e| PbsRunnerError::InternalError(e.to_string()))?;

                    new_proof_setup
                }};
                Ok(Arc::new(proof_setup))
            })
            .await?
            .clone();

        Ok(setup)
    }

    /// Given a SHA2 hash of a ZK program, get the require setup.
    /// The setup is a very heavy task and produces a large output (~200MB),
    /// fortunately it's identical per ZK program, so we store this in a DB to recall it.
    /// We load it and return a pointer to a single instance of this large setup object
    /// to read from for many concurrent [Job]s.
    pub async fn get_proof_setup_remote(
        &self,
        zk_program_elf_sha2: &[u8; 32],
        zk_client_handle: Arc<SP1NetworkProver>,
    ) -> Result<Arc<SP1ProofSetup>, PbsRunnerError> {
        debug!("Getting ZK program proof setup");
        let setup = CHACHA_SETUP
            .get_or_try_init(|| async {
                // Check DB for existing pre-computed setup
                let precomputed_proof_setup = self
                    .config_db
                    .get(zk_program_elf_sha2)
                    .map_err(|e| PbsRunnerError::InternalError(e.to_string()))?;

                let proof_setup = match precomputed_proof_setup { Some(precomputed) => {
                    bincode::deserialize(&precomputed)
                        .map_err(|e| PbsRunnerError::InternalError(e.to_string()))?
                } _ => {
                    info!(
                        "No ZK proof setup in DB for SHA2_256 = 0x{} -- generation & storing in config DB",
                        hex::encode(zk_program_elf_sha2)
                    );

                    let new_proof_setup: SP1ProofSetup = tokio::task::spawn_blocking(move || {
                        zk_client_handle.setup(CHACHA_ELF).into()
                    })
                    .await
                    .map_err(|e| PbsRunnerError::InternalError(e.to_string()))?;

                    self.config_db
                        .insert(
                        zk_program_elf_sha2,
                        bincode::serialize(&new_proof_setup)
                            .map_err(|e| PbsRunnerError::InternalError(e.to_string()))?,
                        )
                        .map_err(|e| PbsRunnerError::InternalError(e.to_string()))?;

                    new_proof_setup
                }};
                Ok(Arc::new(proof_setup))
            })
            .await?
            .clone();

        Ok(setup)
    }

    /// Helper function to handle error from a SP1 NetworkProver Clients.
    /// Will finalize the job in an [JobStatus::Failed] state,
    /// that may be retry-able.
    fn handle_zk_client_error(
        &self,
        zk_client_error: &SP1NetworkError,
        job: &Job,
        job_key: &[u8],
    ) -> PbsRunnerError {
        error!("SP1 Client error: {zk_client_error}");
        let (e, job_status);
        match zk_client_error {
            SP1NetworkError::SimulationFailed | SP1NetworkError::RequestUnexecutable { .. } => {
                e = PbsRunnerError::ZkClientError(format!(
                    "ZKP program critical failure: {zk_client_error} occurred for {job:?} PLEASE REPORT!"
                ));
                job_status = JobStatus::Failed(e.clone(), None);
            }
            SP1NetworkError::RequestUnfulfillable { .. } => {
                e = PbsRunnerError::ZkClientError(format!(
                    "ZKP network failure: {zk_client_error} occurred for {job:?} PLEASE REPORT!"
                ));
                job_status = JobStatus::Failed(e.clone(), None);
            }
            SP1NetworkError::RequestTimedOut { .. }
            | SP1NetworkError::RequestAuctionTimedOut { .. } => {
                e = PbsRunnerError::ZkClientError(format!(
                    "ZKP network: {zk_client_error} occurred for {job:?} - callback to start the job over"
                ));

                // TODO: We cannot clone KeccakInclusionToDataRootProofInput thus we cannot insert into a JobStatus::DataAvailable(proof_input)
                // So we just redo the work from scratch for the DA side as a stupid workaround
                job_status =
                    JobStatus::Failed(e.clone(), Some(JobStatus::RemoteZkProofRequesting.into()));
            }
            SP1NetworkError::RpcError(_) | SP1NetworkError::Other(_) => {
                e = PbsRunnerError::ZkClientError(format!(
                    "ZKP network failure: {zk_client_error} occurred for {job:?} PLEASE REPORT!"
                ));
                // TODO: We cannot clone KeccakInclusionToDataRootProofInput thus we cannot insert into a JobStatus::DataAvailable(proof_input)
                // So we just redo the work from scratch for the DA side as a stupid workaround
                job_status =
                    JobStatus::Failed(e.clone(), Some(JobStatus::RemoteZkProofRequesting.into()));
            }
        }
        match self.finalize_job(job_key, job_status) {
            Ok(_) => e,
            Err(internal_err) => internal_err,
        }
    }

    async fn zk_proof_local(
        &self,
        program_id: &SuccNetProgramId,
        job: &Job,
        job_key: &[u8],
    ) -> Result<SP1ProofWithPublicValues, PbsRunnerError> {
        debug!("Preparing local SP1 proving");
        let zk_client_handle = self.get_zk_client_local().await;
        let proof_setup = self
            .get_proof_setup_local(program_id, zk_client_handle.clone())
            .await?;

        let mut stdin = SP1Stdin::new();
        // Setup the inputs:
        // - key = 32 bytes
        // - nonce = 12 bytes (MUST BE UNIQUE - NO REUSE!)
        // - input_plaintext = bytes to encrypt

        let key = <[u8; 32]>::from_hex(
            std::env::var("ENCRYPTION_KEY").expect("Missing ENCRYPTION_KEY env var"),
        )
        .expect("ENCRYPTION_KEY must be 32 bytes, hex encoded (ex: `1234...abcd`)");

        stdin.write_slice(&key);

        let nonce: [u8; 12] = util::random_nonce();
        stdin.write_slice(&nonce);

        // TODO: replace example bytes with service interface
        let input_plaintext: &[u8] = job.input.data.as_slice();
        stdin.write_slice(input_plaintext);

        debug!("0x{} - Starting proof", hex::encode(job_key));
        let proof = zk_client_handle
            .prove(&proof_setup.pk, &stdin)
            .groth16()
            .run()
            // TODO: how to handle errors without a concrete type? Anyhow is not the right thing for us...
            .map_err(|e| {
                if let Some(down) = e.downcast_ref::<SP1NetworkError>() {
                    return self.handle_zk_client_error(down, job, job_key);
                }
                error!("Unhandled Error: {e:?}");
                PbsRunnerError::ZkClientError(format!("Unhandled Error: {e} PLEASE REPORT"))
            })?;
        debug!("0x{} - Proof complete", hex::encode(job_key));
        Ok(proof)
    }

    async fn zk_proof_remote(
        &self,
        program_id: &SuccNetProgramId,
        job: &Job,
        job_key: &[u8],
    ) -> Result<util::SuccNetJobId, PbsRunnerError> {
        debug!("Preparing *REMOTE* SP1 proving");
        let zk_client_handle = self.get_zk_client_remote().await;
        let proof_setup = self
            .get_proof_setup_remote(program_id, zk_client_handle.clone())
            .await?;

        let fs_string = std::env::var("SP1_FULFILLMENT_STRATEGY")
            .expect("Missing SP1_FULFILLMENT_STRATEGY env var");
        let strategy = FulfillmentStrategy::from_str_name(fs_string.as_str()).ok_or(
            PbsRunnerError::InternalError("SP1_FULFILLMENT_STRATEGY env var malformed".to_string()),
        )?;

        let mut stdin = SP1Stdin::new();
        // Setup the inputs:
        // - key = 32 bytes
        // - nonce = 12 bytes (MUST BE UNIQUE - NO REUSE!)
        // - input_plaintext = bytes to encrypt

        let key = <[u8; 32]>::from_hex(
            std::env::var("ENCRYPTION_KEY").expect("Missing ENCRYPTION_KEY env var"),
        )
        .expect("ENCRYPTION_KEY must be 32 bytes, hex encoded (ex: `1234...abcd`)");

        stdin.write_slice(&key);

        let nonce: [u8; 12] = util::random_nonce();
        stdin.write_slice(&nonce);

        // TODO: replace example bytes with service interface
        let input_plaintext: &[u8] = job.input.data.as_slice();
        stdin.write_slice(input_plaintext);

        debug!("0x{} - Starting proof", hex::encode(job_key));
        let request_id: util::SuccNetJobId = zk_client_handle
            .prove(&proof_setup.pk, &stdin)
            .strategy(strategy)
            .groth16()
            .skip_simulation(false)
            .timeout(self.config.zk_proof_gen_timeout_remote) // Time allowed for provers to *attempt* a job, or it permanently fails.
            .auction_timeout(self.config.zk_proof_auction_timeout_remote)
            .request_async()
            .await
            // TODO: how to handle errors without a concrete type? Anyhow is not the right thing for us...
            .map_err(|e| {
                if let Some(down) = e.downcast_ref::<SP1NetworkError>() {
                    return self.handle_zk_client_error(down, job, job_key);
                }
                PbsRunnerError::ZkClientError(format!("Unhandled Error: {e} PLEASE REPORT"))
            })?
            .into();

        debug!(
            "0x{} - Proof submitted to prover network (Request ID)",
            hex::encode(request_id)
        );
        Ok(request_id)
    }

    /// Await a proof request from Succinct's prover network
    async fn wait_for_zk_proof(
        &self,
        job: &Job,
        job_key: &[u8],
        request_id: util::SuccNetJobId,
    ) -> Result<SP1ProofWithPublicValues, PbsRunnerError> {
        debug!(
            "Waiting for prover network auction to settle with timeout: {} seconds",
            self.config.zk_proof_auction_timeout_remote.as_secs()
        );
        debug!(
            "Waiting for proof generation with timeout: {} seconds",
            self.config.zk_proof_gen_timeout_remote.as_secs()
        );
        let zk_client_handle = self.get_zk_client_remote().await;

        let proof = zk_client_handle
            .wait_proof(
                request_id.into(),
                Some(self.config.zk_proof_gen_timeout_remote),
                Some(self.config.zk_proof_auction_timeout_remote),
            )
            .await
            .map_err(|e| {
                if let Some(down) = e.downcast_ref::<SP1NetworkError>() {
                    return self.handle_zk_client_error(down, job, job_key);
                }
                error!("UNHANDLED ZK client error: {e:?}");
                PbsRunnerError::ZkClientError(format!("Unhandled Error: {e} PLEASE REPORT"))
            })?;

        Ok(proof)
    }

    /// Atomically move a job from the database queue tree to the proof tree.
    /// This removes the job from any further processing by workers.
    /// The [JobStatus] should be success or failure only
    /// (but this is not enforced or checked at this time)
    fn finalize_job(&self, job_key: &[u8], job_status: JobStatus) -> Result<(), PbsRunnerError> {
        // TODO: do we want to do a status check here? To prevent accidentally getting into a DB invalid state
        (&self.queue_db, &self.finished_db)
            .transaction(|(queue_tx, finished_tx)| {
                queue_tx.remove(job_key)?;
                finished_tx.insert(
                    job_key,
                    bincode::serialize(&job_status).expect("Always given serializable job status"),
                )?;
                Ok::<(), sled::transaction::ConflictableTransactionError<PbsRunnerError>>(())
            })
            .map_err(|e| PbsRunnerError::InternalError(e.to_string()))?;
        Ok(())
    }

    /// Insert a [JobStatus] into a [SledTree] database
    /// AND `send()` this job back to the `self.job_sender` to schedule more progress.
    /// You likely want to pass `self.some_sled_tree` into `data_base` as input.
    fn send_job_with_new_status(
        &self,
        job_key: Vec<u8>,
        update_status: JobStatus,
        job: Job,
    ) -> Result<(), PbsRunnerError> {
        debug!(
            "Sending job 0x{} back with updated status: {update_status:?}",
            hex::encode(&job_key)
        );
        (&self.queue_db, &self.finished_db)
            .transaction(|(queue_tx, finished_tx)| {
                finished_tx.remove(job_key.clone())?;
                queue_tx.insert(
                    job_key.clone(),
                    bincode::serialize(&update_status)
                        .expect("Always given serializable job status"),
                )?;
                Ok::<(), sled::transaction::ConflictableTransactionError<PbsRunnerError>>(())
            })
            .map_err(|e| PbsRunnerError::InternalError(e.to_string()))?;
        self.job_sender
            .send(Some(job))
            .map_err(|e| PbsRunnerError::InternalError(e.to_string()))
    }

    pub async fn get_zk_client_local(&self) -> Arc<SP1EnvProver> {
        self.zk_client_handle_local
            .get_or_init(|| async {
                debug!("Building Local ZK client");
                let client = sp1_sdk::ProverClient::from_env();
                Arc::new(client)
            })
            .await
            .clone()
    }

    pub async fn get_zk_client_remote(&self) -> Arc<SP1NetworkProver> {
        self.zk_client_handle_remote
            .get_or_init(|| async {
                debug!("Building Remote ZK client");
                let client = sp1_sdk::ProverClient::builder().network().build();
                Arc::new(client)
            })
            .await
            .clone()
    }

    pub fn shutdown(&self) {
        info!("Terminating worker,finishing preexisting jobs");
        let _ = self.job_sender.send(None); // Break loop in `job_worker`
    }
}
