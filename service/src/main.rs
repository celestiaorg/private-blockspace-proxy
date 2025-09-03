use async_trait::async_trait;
use bytes::Bytes;
use hex::FromHex;
use log::{debug, info, warn};
use pingora_core::ErrorType;
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use url::Url;
use zkvm_common::std_only::ZkvmOutput;

use pingora_core::server::{Server, configuration::Opt};
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::{Error as PgError, Result as PgResult};
use pingora_http::ResponseHeader;
use pingora_proxy::{ProxyHttp, Session, http_proxy_service};

use celestia_client::Client as CelClient;
use celestia_client::tx::TxConfig;
use celestia_client::types::{AppVersion, Blob};

use sha2::{Digest, Sha256};
use sp1_sdk::SP1ProofWithPublicValues;
use tokio::sync::{OnceCell, mpsc};

mod internal;
use internal::error::*;
use internal::job::*;
use internal::runner::*;
use internal::util::*;

use zkvm_common::chacha;

#[derive(Clone)]
struct App {
    /// Upstream Celestia node for non-intercepted methods (e.g., blob.Get/GetAll).
    /// Requires string of form "https://some-node.com:26658" - http and https are supported.
    upstream_da_node_uri: String,

    /// Celestia client (submit mode) for signing + submitting.
    cel_client: Arc<CelClient>,

    /// Job runner (zk proof generation).
    job_runner: Arc<PdaRunner>,
}

struct SessionContext {
    /// Buffer used if we need to rewrite the response body (e.g., decrypt).
    buffer: Vec<u8>,
    /// What method was called (so response filters know whether to decrypt).
    request_method: Option<String>,
}

#[async_trait]
impl ProxyHttp for App {
    type CTX = SessionContext;

    fn new_ctx(&self) -> Self::CTX {
        SessionContext {
            buffer: vec![],
            request_method: None,
        }
    }

    // Select the upstream peer for normal proxying
    // NOTE: Assumes READ ONLY node RPC is only passthrough
    async fn upstream_peer(
        &self,
        _s: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> PgResult<Box<HttpPeer>> {
        let (address, tls, sni) = parse_http_peer_from_uri(&self.upstream_da_node_uri)?;
        Ok(Box::new(HttpPeer::new(address, tls, sni)))
    }

    async fn request_filter(&self, s: &mut Session, ctx: &mut Self::CTX) -> PgResult<bool> {
        // IMPORTANT: enable buffering BEFORE reading the body
        // We can forward buffer if we return Ok(false)
        s.enable_retry_buffering();

        let body_opt = s.read_request_body().await?;
        let Some(body) = body_opt else {
            return Ok(false);
        };

        let mut body_json: Value = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(_) => return Ok(false),
        };

        let method = body_json
            .get("method")
            .and_then(|m| m.as_str())
            .unwrap_or("")
            .to_owned();

        // Cache the method we saw on the request to handle response
        ctx.request_method = Some(method.clone());

        match method.as_str() {
            "blob.Submit" => {
                debug!("blob.Submit: Intercepted!");
                let Some(params) = body_json.get_mut("params") else {
                    return self.bad_req(s, "missing params").await;
                };
                let arr = params.as_array_mut().ok_or_else(|| {
                    PgError::explain(ErrorType::InternalError, "params not array")
                })?;
                if arr.is_empty() {
                    return self.bad_req(s, "empty params").await;
                }
                let blobs_val = arr
                    .get_mut(0)
                    .ok_or_else(|| PgError::explain(ErrorType::InternalError, "missing blobs"))?;
                let incoming_blobs: Vec<Blob> = serde_json::from_value(std::mem::take(blobs_val))
                    .map_err(|e| {
                    PgError::because(ErrorType::InternalError, "blob deserialize", e)
                })?;

                debug!(
                    "blob.Submit: Starting or checking job stats for {} blobs",
                    incoming_blobs.len()
                );
                let encrypted: Vec<Blob> = {
                    let mut out = Vec::with_capacity(incoming_blobs.len());
                    for blob in incoming_blobs {
                        let data = blob.data.clone();
                        let job = Job {
                            anchor: Anchor {
                                data: Sha256::digest(&data).as_slice().into(),
                            },
                            input: Input { data },
                        };

                        let Some(pwv) = self
                            .job_runner
                            .get_verifiable_encryption(job)
                            .await
                            .map_err(|e| {
                                PgError::because(
                                    ErrorType::Custom("ZKProofFailure"),
                                    "Proof Generation",
                                    e,
                                )
                            })?
                        else {
                            debug!("blob.Submit: jobs pending... call back");
                            // 202 Pending — instruct client to poll later
                            return self.pending(s).await;
                        };

                        let enc = bincode::serialize(&pwv).map_err(|e| {
                            PgError::because(ErrorType::InternalError, "Proof serialize", e)
                        })?;

                        let b =
                            Blob::new(blob.namespace, enc, AppVersion::latest()).map_err(|e| {
                                PgError::because(ErrorType::InternalError, "Blob Create", e)
                            })?;
                        out.push(b);
                    }
                    out // <- dropped here
                };

                debug!("blob.Submit: jobs finished! Submitting...");
                let enc_owned = encrypted;
                let client = self.cel_client.clone();
                let cfg = TxConfig::default();

                let tx_info = submit_via_blocking_thread(client, enc_owned, cfg).await?;

                // --------- respond JSON-RPC (await) ----------
                let resp = json!({
                    "jsonrpc": "2.0",
                    "result": {
                        "txhash": tx_info.hash,
                        "height": tx_info.height,
                    },
                    "id": body_json.get("id").cloned().unwrap_or(json!(1)),
                });

                let mut hdr = ResponseHeader::build(200, None).unwrap();
                hdr.insert_header("content-type", "application/json").ok();
                s.write_response_header(Box::new(hdr), false).await?;
                s.write_response_body(Some(Bytes::from(serde_json::to_vec(&resp).unwrap())), true)
                    .await?;
                Ok(true)
            }

            // Short-circuit filter and transparently proxy request through
            _ => Ok(false),
        }
    }

    async fn response_filter(
        &self,
        _s: &mut Session,
        upstream_resp: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> PgResult<()> {
        debug!("response!@!!");
        // If we’ll rewrite the body, remove Content-Length and switch to chunked
        if matches!(
            ctx.request_method.as_deref(),
            Some("blob.Get" | "blob.GetAll")
        ) {
            upstream_resp.remove_header("Content-Length");
            upstream_resp
                .insert_header("Transfer-Encoding", "chunked")
                .ok();
        }
        Ok(())
    }

    fn response_body_filter(
        &self,
        _s: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<Option<std::time::Duration>> {
        if matches!(
            ctx.request_method.as_deref(),
            Some("blob.Get" | "blob.GetAll")
        ) {
            if let Some(b) = body {
                ctx.buffer.extend_from_slice(b);
                b.clear();
            }
            if end_of_stream {
                // Run the async decrypt *synchronously* without starting a nested runtime.
                let out =
                    match tokio::task::block_in_place(|| {
                        tokio::runtime::Handle::current().block_on(self.try_decrypt_response(
                            &ctx.buffer,
                            ctx.request_method.as_deref().unwrap(),
                        ))
                    }) {
                        Ok(v) => v,
                        Err(e) => {
                            warn!("Failed to decrypt response: {e}");
                            ctx.buffer.clone()
                        }
                    };
                *body = Some(Bytes::from(out));
            }
        }
        Ok(None)
    }
}

impl App {
    async fn bad_req(&self, s: &mut Session, msg: &str) -> PgResult<bool> {
        let payload =
            json!({ "jsonrpc":"2.0", "error": { "code": -32602, "message": msg }, "id": 1 })
                .to_string();
        let mut hdr = ResponseHeader::build(400, None).unwrap();
        hdr.insert_header("content-type", "application/json").ok();
        s.write_response_header(Box::new(hdr), false).await?;
        s.write_response_body(Some(Bytes::from(payload)), true)
            .await?;
        Ok(true)
    }

    async fn pending(&self, s: &mut Session) -> PgResult<bool> {
        let payload = r#"{ "id": 1, "jsonrpc": "2.0", "status": "[pda-proxy] Verifiable encryption processing... Call back for result" }"#;
        let mut hdr = ResponseHeader::build(202, None).unwrap();
        hdr.insert_header("content-type", "application/json").ok();
        s.write_response_header(Box::new(hdr), false).await?;
        s.write_response_body(Some(Bytes::from_static(payload.as_bytes())), true)
            .await?;
        Ok(true)
    }

    pub async fn try_decrypt_response(&self, body: &[u8], method: &str) -> PgResult<Vec<u8>> {
        let mut v: Value = serde_json::from_slice(body).map_err(|e| {
            PgError::because(ErrorType::InternalError, "Failed to parse response JSON", e)
        })?;

        let result = v.get_mut("result").ok_or_else(|| {
            PgError::because(ErrorType::InternalError, "Missing 'result' in response", "")
        })?;

        let key_env = std::env::var("ENCRYPTION_KEY")
            .map_err(|e| PgError::because(ErrorType::InternalError, "ENCRYPTION_KEY not set", e))?;

        let key = <[u8; 32]>::from_hex(key_env).map_err(|e| {
            PgError::because(ErrorType::InternalError, "Invalid ENCRYPTION_KEY hex", e)
        })?;

        let runner = self.job_runner.clone();

        // Helper to decrypt one blob (async, no boxing)
        async fn decrypt_one(
            mut blob: Blob,
            encryption_key: [u8; 32],
            runner: Arc<PdaRunner>,
        ) -> PgResult<Blob> {
            let proof: SP1ProofWithPublicValues =
                bincode::deserialize(&blob.data).map_err(|e| {
                    PgError::because(
                        ErrorType::InternalError,
                        "Failed to decode SP1 proof from blob.data",
                        e,
                    )
                })?;

            let output = extract_verified_proof_output(&proof, runner)
                .await
                .map_err(|e| {
                    PgError::because(ErrorType::InternalError, "Failed to verify SP1 proof", e)
                })?;

            let mut buf = output.ciphertext.to_owned();
            chacha(&encryption_key, &output.nonce, &mut buf);
            blob.data = buf;
            Ok(blob)
        }

        match method {
            "blob.Get" => {
                let blob: Blob = serde_json::from_value(result.clone()).map_err(|e| {
                    PgError::because(ErrorType::InternalError, "Failed to decode Blob", e)
                })?;
                let decrypted = decrypt_one(blob, key, runner).await?;
                *result = serde_json::to_value(decrypted).map_err(|e| {
                    PgError::because(
                        ErrorType::InternalError,
                        "Failed to encode decrypted Blob",
                        e,
                    )
                })?;
            }
            "blob.GetAll" => {
                let arr = result.as_array().ok_or_else(|| {
                    PgError::because(ErrorType::InternalError, "'result' is not an array", "")
                })?;

                // Deserialize -> decrypt sequentially -> re-serialize (keeps order, simple)
                let mut out = Vec::with_capacity(arr.len());
                for b in arr {
                    let blob: Blob = serde_json::from_value(b.clone()).map_err(|e| {
                        PgError::because(
                            ErrorType::InternalError,
                            "Failed to decode Blob in array",
                            e,
                        )
                    })?;
                    let dec = decrypt_one(blob, key, runner.clone()).await?;
                    let val = serde_json::to_value(dec).map_err(|e| {
                        PgError::because(
                            ErrorType::InternalError,
                            "Failed to encode decrypted Blob",
                            e,
                        )
                    })?;
                    out.push(val);
                }
                *result = Value::Array(out);
            }
            _ => { /* no-op for other methods */ }
        }

        serde_json::to_vec(&v).map_err(|e| {
            PgError::because(
                ErrorType::InternalError,
                "Failed to serialize response JSON",
                e,
            )
        })
    }
}

fn main() -> PgResult<()> {
    env_logger::init();

    let pda_socket = std::env::var("PDA_SOCKET")
        .map_err(|e| PgError::because(ErrorType::InternalError, "PDA_SOCKET required", e))?;

    // Resolve DNS of upstream providers of Core/App and DA nodes
    let node_rpc = std::env::var("CELESTIA_NODE_RPC")
        .map_err(|e| PgError::because(ErrorType::InternalError, "CELESTIA_NODE_RPC required", e))?;
    let core_grpc = std::env::var("CELESTIA_CORE_GRPC").map_err(|e| {
        PgError::because(ErrorType::InternalError, "CELESTIA_CORE_GRPC required", e)
    })?;

    let signer_key_hex = std::env::var("CELESTIA_SIGNING_KEY").map_err(|e| {
        PgError::because(ErrorType::InternalError, "Missing CELESTIA_SIGNING_KEY", e)
    })?;
    let signer_key = <[u8; 32]>::from_hex(signer_key_hex).map_err(|e| {
        PgError::because(
            ErrorType::InternalError,
            "CELESTIA_SIGNING_KEY must be 32 hex bytes",
            e,
        )
    })?;

    // Validate encryption key, so further calls to use it succeed
    let enc_key_hex = std::env::var("ENCRYPTION_KEY")
        .map_err(|e| PgError::because(ErrorType::InternalError, "Missing ENCRYPTION_KEY", e))?;
    let _ = <[u8; 32]>::from_hex(enc_key_hex).map_err(|e| {
        PgError::because(
            ErrorType::InternalError,
            "ENCRYPTION_KEY must be 32 hex bytes",
            e,
        )
    })?;

    // Setup DB and Job runner
    let db_path = std::env::var("PDA_DB_PATH")
        .map_err(|e| PgError::because(ErrorType::InternalError, "PDA_DB_PATH required", e))?;
    let db = sled::open(&db_path)
        .map_err(|e| PgError::because(ErrorType::InternalError, "Open sled DB", e))?;
    let config_db = db
        .open_tree("config")
        .map_err(|e| PgError::because(ErrorType::InternalError, "Open sled tree: config", e))?;
    let queue_db = db
        .open_tree("queue")
        .map_err(|e| PgError::because(ErrorType::InternalError, "Open sled tree: queue", e))?;
    let finished_db = db
        .open_tree("finished")
        .map_err(|e| PgError::because(ErrorType::InternalError, "Open sled tree: finished", e))?;

    let zk_proof_auction_timeout_remote = Duration::from_secs(
        std::env::var("PROOF_AUCTION_TIMEOUT_SECONDS_REMOTE")
            .map_err(|e| {
                PgError::because(
                    ErrorType::InternalError,
                    "Missing PROOF_AUCTION_TIMEOUT_SECONDS_REMOTE",
                    e,
                )
            })?
            .parse::<u64>()
            .map_err(|e| {
                PgError::because(
                    ErrorType::InternalError,
                    "Parse PROOF_AUCTION_TIMEOUT_SECONDS_REMOTE",
                    e,
                )
            })?,
    );

    let zk_proof_gen_timeout_remote = Duration::from_secs(
        std::env::var("PROOF_GEN_TIMEOUT_SECONDS_REMOTE")
            .map_err(|e| {
                PgError::because(
                    ErrorType::InternalError,
                    "Missing PROOF_GEN_TIMEOUT_SECONDS_REMOTE",
                    e,
                )
            })?
            .parse::<u64>()
            .map_err(|e| {
                PgError::because(
                    ErrorType::InternalError,
                    "Parse PROOF_GEN_TIMEOUT_SECONDS_REMOTE",
                    e,
                )
            })?,
    );

    let (job_sender, job_receiver) = mpsc::unbounded_channel::<Option<Job>>();
    let pda_runner = Arc::new(PdaRunner::new(
        PdaRunnerConfig {
            zk_proof_gen_timeout_remote,
            zk_proof_auction_timeout_remote,
        },
        OnceCell::new(),
        OnceCell::new(),
        config_db.clone(),
        queue_db.clone(),
        finished_db.clone(),
        job_sender.clone(),
    ));

    // Restart queued jobs (sync)
    debug!("Restarting queued jobs");
    for (job_key, queue_data) in queue_db.iter().flatten() {
        let job: Job = bincode::deserialize(&job_key).unwrap();
        if let Ok(st) = bincode::deserialize::<JobStatus>(&queue_data) {
            if matches!(
                st,
                JobStatus::LocalZkProofPending | JobStatus::RemoteZkProofPending(_)
            ) {
                let _ = job_sender.send(Some(job));
            }
        }
    }

    // Dedicated background runtime thread for long-lived tasks
    // NOTE: this is required as Pingora creates it's own Tokio runtime and it must own it.
    {
        let runner = pda_runner.clone();
        let job_rx = job_receiver;

        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("build background tokio runtime");

            rt.block_on(async move {
                // Warm ZK clients before entering long-lived loop
                let program_id = get_program_id().await;
                let zk_local = runner.clone().get_zk_client_local().await;
                let zk_remote = runner.clone().get_zk_client_remote().await;
                let _ = runner.get_proof_setup_local(&program_id, zk_local).await;
                let _ = runner.get_proof_setup_remote(&program_id, zk_remote).await;
                info!("ZK clients ready!");

                // Wait for either shutdown or job_worker completion (whichever happens first)
                tokio::select! {
                    _ = runner.clone().job_worker(job_rx) => {},
                    _ = async {
                        wait_shutdown_signals().await;
                        runner.shutdown();
                    } => {},
                }
                info!("Background runtime exiting");
            });
        });
    }

    // Async initialization before server starts using a TEMP runtime
    let cel_client = {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| {
                PgError::because(ErrorType::InternalError, "Build temp tokio runtime", e)
            })?;

        let client = rt.block_on(async {
            CelClient::builder()
                .rpc_url(&node_rpc)
                .grpc_url(&core_grpc)
                .private_key(&signer_key)
                .build()
                .await
                .map_err(|e| PgError::because(ErrorType::InternalError, "Build Celestia client", e))
        })?;
        Arc::new(client)
    };
    info!("Celestia client (submit mode) ready!");

    // Start Pingora HTTP proxy service (Pingora owns its runtime)
    let opt = Opt::default();
    let mut server = Server::new(Some(opt))?;
    server.bootstrap();

    let mut pda_service = http_proxy_service(
        &server.configuration,
        App {
            upstream_da_node_uri: node_rpc.clone(),
            cel_client,
            job_runner: pda_runner.clone(),
        },
    );

    // Listener (plain TCP). If you need TLS on Pingora, wire a TLS listener per Pingora docs.
    pda_service.add_tcp(&pda_socket);
    server.add_service(pda_service);
    info!("Listening on http://{pda_socket} — proxying to {node_rpc} (submit to {core_grpc})");
    server.run_forever();
}

// ============================== Helpers ==============================

/// Verify a proof before returning its attested output
async fn extract_verified_proof_output<'a>(
    proof: &'a SP1ProofWithPublicValues,
    runner: Arc<PdaRunner>,
) -> PgResult<ZkvmOutput<'a>> {
    let zk_client_local = runner.get_zk_client_local().await;

    let setup = runner
        .get_proof_setup_local(&get_program_id().await, zk_client_local.clone())
        .await
        .map_err(|e| {
            PgError::because(
                ErrorType::InternalError,
                "Failed to load local proof setup (vk)",
                e,
            )
        })?;

    zk_client_local
        .verify(proof, &setup.vk)
        .map_err(|e| PgError::because(ErrorType::InternalError, "Proof verification failed", e))?;

    ZkvmOutput::from_bytes(proof.public_values.as_slice()).map_err(|e| {
        PgError::because(
            ErrorType::InternalError,
            "Failed to decode ZkvmOutput from public values",
            e,
        )
    })
}

/// Helper: submit a blob via a non-Send async future by blocking on a background thread
async fn submit_via_blocking_thread(
    client: Arc<CelClient>,
    encrypted: Vec<Blob>,
    cfg: TxConfig,
) -> PgResult<celestia_client::tx::TxInfo> {
    let res = tokio::task::spawn_blocking(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| {
                PgError::because(ErrorType::InternalError, "Build single-thread runtime", e)
            })?;
        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, async move {
            client
                .blob()
                .submit(&encrypted, cfg)
                .await
                .map_err(|e| PgError::because(ErrorType::WriteError, "Blob submit failed", e))
        })
    })
    .await
    .map_err(|e| PgError::because(ErrorType::InternalError, "Join blocking submit thread", e))??;

    Ok(res)
}

/// Parse URI string ("https://some.site:8080") into (addr, tls, sni) for `HttpPeer::new()`
fn parse_http_peer_from_uri(uri: &str) -> PgResult<(String, bool, String)> {
    let url = Url::parse(uri)
        .map_err(|e| PgError::because(ErrorType::InternalError, "Invalid upstream URI", e))?;

    // enforce supported schemes
    let tls = match url.scheme() {
        "http" => false,
        "https" => true,
        other => {
            return Err(PgError::because(
                ErrorType::InternalError,
                format!("Unsupported scheme `{other}`"),
                "",
            ));
        }
    };

    let host = url
        .host_str()
        .ok_or_else(|| {
            PgError::because(ErrorType::InternalError, "Missing host in upstream URI", "")
        })?
        .to_string();

    let port = url.port().ok_or_else(|| {
        PgError::because(ErrorType::InternalError, "Missing port in upstream URI", "")
    })?;

    let addr = format!("{host}:{port}");
    let sni = host.clone(); // use host as SNI (even if IP)
    Ok((addr, tls, sni))
}
