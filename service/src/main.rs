use async_trait::async_trait;
use bytes::Bytes;
use hex::FromHex;
use log::{debug, info, warn};
use pingora_core::ErrorType;
use serde_json::{Value, json};
use std::{net::ToSocketAddrs, sync::Arc, time::Duration};
use zkvm_common::std_only::ZkvmOutput;

use pingora_core::server::{Server, configuration::Opt};
use pingora_core::upstreams::peer::HttpPeer;
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

// ---------------------------- App State ----------------------------

#[derive(Clone)]
struct App {
    // Upstream Celestia node for non-intercepted methods (e.g., blob.Get/GetAll)
    upstream_addr: std::net::SocketAddr,
    upstream_host: String,

    // High-level Celestia client (submit mode) for signing + submitting
    cel: Arc<CelClient>,

    // Your existing runner (for proofs, encryption/decryption)
    pda_runner: Arc<PdaRunner>,
}

struct Ctx {
    /// Buffer used if we need to rewrite the response body (e.g., decrypt)
    buffer: Vec<u8>,
    /// What method was called (so response filters know whether to decrypt)
    request_method: Option<String>,
}

#[async_trait]
impl ProxyHttp for App {
    type CTX = Ctx;

    fn new_ctx(&self) -> Self::CTX {
        Ctx {
            buffer: vec![],
            request_method: None,
        }
    }

    // Select the upstream peer for normal proxying
    async fn upstream_peer(
        &self,
        _s: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> pingora_core::Result<Box<HttpPeer>> {
        Ok(Box::new(HttpPeer::new(
            self.upstream_addr,
            false,
            self.upstream_host.clone(),
        )))
    }

    async fn request_filter(
        &self,
        s: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<bool> {
        // ---- read body (await) ----
        let body_opt = s.read_request_body().await?;
        let Some(body) = body_opt else {
            return Ok(false);
        };

        // ---- parse JSON (no await) ----
        let mut body_json: Value = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(_) => return Ok(false),
        };

        // ---- method bookkeeping (no await) ----
        let method = body_json
            .get("method")
            .and_then(|m| m.as_str())
            .unwrap_or("")
            .to_owned();
        ctx.request_method = Some(method.clone());

        match method.as_str() {
            "blob.Submit" => {
                // --------- validate/deserialize params (no await) ----------
                let Some(params) = body_json.get_mut("params") else {
                    return self.bad_req(s, "missing params").await;
                };
                let arr = params.as_array_mut().ok_or_else(|| {
                    pingora_core::Error::explain(ErrorType::InternalError, "params not array")
                })?;
                if arr.is_empty() {
                    return self.bad_req(s, "empty params").await;
                }
                let blobs_val = arr.get_mut(0).ok_or_else(|| {
                    pingora_core::Error::explain(ErrorType::InternalError, "missing blobs")
                })?;
                let incoming_blobs: Vec<Blob> = serde_json::from_value(std::mem::take(blobs_val))
                    .map_err(|e| {
                    pingora_core::Error::because(ErrorType::InternalError, "blob deserialize", e)
                })?;

                // --------- encrypt/prove (awaits occur here; scope them) ----------
                // All ephemeral/non-Send items (RNGs, contexts) stay within this block and are dropped
                // before we run the non-Send submit on a local runtime.
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
                            .pda_runner
                            .get_verifiable_encryption(job)
                            .await
                            .map_err(|e| {
                                pingora_core::Error::because(
                                    ErrorType::Custom("ZKProofFailure"),
                                    "Proof Generation",
                                    e,
                                )
                            })?
                        else {
                            // 202 Pending — instruct client to poll later
                            return self.pending(s).await;
                        };

                        let enc = bincode::serialize(&pwv).map_err(|e| {
                            pingora_core::Error::because(
                                ErrorType::InternalError,
                                "Proof serialize",
                                e,
                            )
                        })?;

                        let b =
                            Blob::new(blob.namespace, enc, AppVersion::latest()).map_err(|e| {
                                pingora_core::Error::because(
                                    ErrorType::InternalError,
                                    "Blob Create",
                                    e,
                                )
                            })?;
                        out.push(b);
                    }
                    out // <- dropped here
                };

                // Prepare owned values for the 'static async block
                let enc_owned = encrypted;
                let client = self.cel.clone();
                let cfg = TxConfig::default();

                let submit_res = run_non_send_async(async move {
                    // nothing captured by reference; all moved in
                    client.blob().submit(&enc_owned, cfg).await
                });

                let tx_info = submit_res.map_err(|e| {
                    pingora_core::Error::because(
                        pingora_core::ErrorType::WriteError,
                        "Blob Submit failed",
                        e,
                    )
                })?;

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

            _ => Ok(false),
        }
    }

    // --------- Response phase: decrypt for blob.Get / blob.GetAll ----------
    async fn response_filter(
        &self,
        _s: &mut Session,
        upstream_resp: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<()> {
        // If we’ll rewrite the body, remove Content-Length and switch to chunked (see example)
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
        // Buffer body if we need to decrypt
        if matches!(
            ctx.request_method.as_deref(),
            Some("blob.Get" | "blob.GetAll")
        ) {
            if let Some(b) = body {
                ctx.buffer.extend_from_slice(b);
                b.clear(); // drop original bytes
            }
            if end_of_stream {
                // SAFETY: If decrypt fails we’ll just return original
                let out = match self
                    .try_decrypt_response(&ctx.buffer, ctx.request_method.as_deref().unwrap())
                {
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
    async fn bad_req(&self, s: &mut Session, msg: &str) -> pingora_core::Result<bool> {
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

    async fn pending(&self, s: &mut Session) -> pingora_core::Result<bool> {
        let payload = r#"{ "id": 1, "jsonrpc": "2.0", "status": "[pda-proxy] Verifiable encryption processing... Call back for result" }"#;
        let mut hdr = ResponseHeader::build(202, None).unwrap();
        hdr.insert_header("content-type", "application/json").ok();
        s.write_response_header(Box::new(hdr), false).await?;
        s.write_response_body(Some(Bytes::from_static(payload.as_bytes())), true)
            .await?;
        Ok(true)
    }

    fn try_decrypt_response(&self, body: &[u8], method: &str) -> anyhow::Result<Vec<u8>> {
        let mut v: Value = serde_json::from_slice(body)?;
        let result = v
            .get_mut("result")
            .ok_or_else(|| anyhow::anyhow!("Missing 'result'"))?;

        let key =
            <[u8; 32]>::from_hex(std::env::var("ENCRYPTION_KEY").expect("Missing ENCRYPTION_KEY"))?;

        // Helpers identical to your originals, inlined here:
        fn decode_one<'a>(
            blob: Blob,
            key: [u8; 32],
            runner: Arc<PdaRunner>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<Blob>> + Send + 'a>>
        {
            Box::pin(async move {
                let proof: SP1ProofWithPublicValues = bincode::deserialize(&blob.data)?;
                let output = extract_verified_proof_output(&proof, runner.clone()).await?;
                let mut buf = output.ciphertext.to_owned();
                chacha(&key, &output.nonce, &mut buf);
                let mut out = blob.clone();
                out.data = buf;
                Ok(out)
            })
        }

        // We need runner here; stash on self
        let runner = self.pda_runner.clone();
        let rt = tokio::runtime::Handle::current();

        match method {
            "blob.Get" => {
                let blob: Blob = serde_json::from_value(result.clone())?;
                let decrypted = rt.block_on(decode_one(blob, key, runner))?;
                *result = serde_json::to_value(decrypted)?;
            }
            "blob.GetAll" => {
                let arr = result
                    .as_array()
                    .ok_or_else(|| anyhow::anyhow!("result not array"))?
                    .clone();
                let futs = arr.into_iter().map(|b| {
                    let blob: Blob = serde_json::from_value(b).unwrap();
                    decode_one(blob, key, runner.clone())
                });

                let mut out = Vec::new();
                let mut set = tokio::task::JoinSet::new();
                for f in futs {
                    set.spawn(f);
                }
                while let Some(res) = rt.block_on(set.join_next()) {
                    let blob = res.map_err(|e| anyhow::anyhow!(e))??; // JoinError -> anyhow, then inner anyhow
                    out.push(serde_json::to_value(blob)?);
                }
                *result = Value::Array(out);
            }
            _ => {}
        }

        Ok(serde_json::to_vec(&v)?)
    }
}

// ---------------------------- Boot ----------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Validate encryption key once (like your original)
    let _ = <[u8; 32]>::from_hex(std::env::var("ENCRYPTION_KEY").expect("Missing ENCRYPTION_KEY"))
        .expect("ENCRYPTION_KEY must be 32 hex bytes");

    // DB and runners kept the same as your original
    let db_path = std::env::var("PDA_DB_PATH").expect("PDA_DB_PATH required");
    let db = sled::open(db_path)?;
    let config_db = db.open_tree("config")?;
    let queue_db = db.open_tree("queue")?;
    let finished_db = db.open_tree("finished")?;

    let zk_proof_auction_timeout_remote =
        Duration::from_secs(std::env::var("PROOF_AUCTION_TIMEOUT_SECONDS_REMOTE")?.parse()?);
    let zk_proof_gen_timeout_remote =
        Duration::from_secs(std::env::var("PROOF_GEN_TIMEOUT_SECONDS_REMOTE")?.parse()?);

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

    // Warm up runner (same as your original spawns)
    {
        let runner = pda_runner.clone();
        tokio::spawn(async move {
            let program_id = get_program_id().await;
            let zk_local = runner.clone().get_zk_client_local().await;
            let zk_remote = runner.clone().get_zk_client_remote().await;
            let _ = runner.get_proof_setup_local(&program_id, zk_local).await;
            let _ = runner.get_proof_setup_remote(&program_id, zk_remote).await;
            info!("ZK client ready!");
        });
    }
    {
        let runner = pda_runner.clone();
        tokio::spawn(async move {
            wait_shutdown_signals().await;
            runner.shutdown();
        });
    }
    {
        let runner = pda_runner.clone();
        tokio::spawn(async move { runner.job_worker(job_receiver).await });
    }
    // Restart queued jobs as before...
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

    // Build celestia_client in submit mode (RPC + gRPC + signer)
    let cel = Arc::new(
        CelClient::builder()
            .rpc_url(&std::env::var("CELESTIA_RPC_WS").unwrap_or("ws://127.0.0.1:26658".into()))
            .grpc_url(
                &std::env::var("CELESTIA_GRPC_HTTP").unwrap_or("http://127.0.0.1:9090".into()),
            )
            .private_key_hex(&std::env::var("CELESTIA_PRIVKEY_HEX")?)
            .build()
            .await?,
    );

    // Upstream Celestia node (HTTP/WS) for *reads* and non-intercepted methods
    let upstream_host = std::env::var("CELESTIA_NODE_HOST").unwrap_or("127.0.0.1".into());
    let upstream_port: u16 = std::env::var("CELESTIA_NODE_PORT")
        .unwrap_or("26658".into())
        .parse()?;
    let upstream_addr = (upstream_host.as_str(), upstream_port)
        .to_socket_addrs()?
        .next()
        .unwrap();

    // Start Pingora HTTP proxy service
    let opt = Opt::default();
    let mut server = Server::new(Some(opt))?;
    server.bootstrap();

    let mut svc = http_proxy_service(
        &server.configuration,
        App {
            upstream_addr,
            upstream_host: upstream_host.clone(),
            cel,
            pda_runner: pda_runner.clone(),
        },
    );

    // Listener (plain TCP). If you need TLS on Pingora, wire a TLS listener per Pingora docs.
    let listen_addr = std::env::var("PDA_SOCKET").unwrap_or("0.0.0.0:8080".into());
    svc.add_tcp(&listen_addr);
    server.add_service(svc);
    info!(
        "Listening on http://{listen_addr} (Pingora) — proxying to {upstream_host}:{upstream_port}"
    );
    server.run_forever();
    // (unreachable)
}

/// Verify a proof before returning it's attested output
async fn extract_verified_proof_output<'a>(
    proof: &'a SP1ProofWithPublicValues,
    runner: Arc<PdaRunner>,
) -> anyhow::Result<ZkvmOutput<'a>> {
    let zk_client_local = runner.get_zk_client_local().await;
    let vk = &runner
        .get_proof_setup_local(&get_program_id().await, zk_client_local.clone())
        .await?
        .vk;
    zk_client_local.verify(proof, vk)?;

    ZkvmOutput::from_bytes(proof.public_values.as_slice()).map_err(anyhow::Error::msg)
}

/// Helper: run a non-Send async future to completion on this thread
fn run_non_send_async<F, T>(fut: F) -> T
where
    F: std::future::Future<Output = T> + 'static, // not Send
    T: 'static,
{
    tokio::task::block_in_place(|| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build current_thread runtime");
        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, fut)
    })
}
