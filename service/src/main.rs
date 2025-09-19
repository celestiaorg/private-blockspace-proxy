use anyhow::Result;
use celestia_client::Client as CelClient;
use celestia_client::tx::TxConfig;
use celestia_client::types::{AppVersion, Blob};
use hex::FromHex;
use http::Uri;
use http::header::HOST;
use http_body_util::{BodyExt, Full};
use hyper::Error as HyperError;
use hyper::{
    Request, Response, StatusCode,
    body::{Buf, Bytes, Incoming as IncomingBody},
    server::conn::http1,
    service::service_fn,
};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use log::{debug, error, info, warn};
use rustls::ServerConfig;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sp1_sdk::SP1ProofWithPublicValues;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    net::TcpListener,
    sync::{OnceCell, mpsc},
};
use tokio_rustls::TlsAcceptor;

mod internal;
use internal::error::*;
use internal::job::*;
use internal::runner::*;
use internal::util::*;

use zkvm_common::{chacha, std_only::ZkvmOutput};

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    // NOTE: leak here to avoid an Arc, this is a var we need for the whole process lifetime
    let node_rpc_uri: &'static Uri = Box::leak(Box::new({
        let uri: Uri = std::env::var("CELESTIA_NODE_RPC")
            .expect("CELESTIA_NODE_RPC env var required (e.g. http://host:26658 or https://...)")
            .parse()
            .expect("CELESTIA_NODE_RPC must be an absolute URI");
        assert!(
            uri.scheme().is_some() && uri.authority().is_some(),
            "CELESTIA_NODE_RPC must include scheme and host:port"
        );
        let mut parts = http::uri::Parts::default();
        parts.scheme = uri.scheme().cloned();
        parts.authority = uri.authority().cloned();
        parts.path_and_query = uri.path_and_query().cloned();
        Uri::from_parts(parts).unwrap()
    }));

    let node_write_token = match std::env::var("CELESTIA_NODE_WRITE_TOKEN") {
        Ok(val) if !val.is_empty() => Some(val),
        _ => {
            warn!("CELESTIA_NODE_WRITE_TOKEN not used");
            None
        }
    };

    let core_grpc_uri = std::env::var("CELESTIA_CORE_GRPC")
        .expect("CELESTIA_CORE_GRPC env var required (e.g. https://host:9090)");

    // TODO: we need to provide a way to use a proper signer, not force it as env!
    let signer_key = <[u8; 32]>::from_hex(
        std::env::var("CELESTIA_SIGNING_KEY").expect("Missing CELESTIA_SIGNING_KEY"),
    )
    .expect("CELESTIA_SIGNING_KEY must be 32 hex bytes");

    // Validate the encryption key at boot
    let _ = <[u8; 32]>::from_hex(
        std::env::var("ENCRYPTION_KEY").expect("Missing ENCRYPTION_KEY env var"),
    )
    .expect("ENCRYPTION_KEY must be 32 bytes hex");

    let db_path = std::env::var("PDA_DB_PATH").expect("PDA_DB_PATH env var required");
    let db = sled::open(db_path.clone())?;
    let config_db = db.open_tree("config")?;
    let queue_db = db.open_tree("queue")?;
    let finished_db = db.open_tree("finished")?;

    let service_socket: SocketAddr = std::env::var("PDA_SOCKET")
        .expect("PDA_SOCKET env var required")
        .parse()
        .expect("PDA_SOCKET cannot parse");

    let _ = rustls::crypto::ring::default_provider().install_default();
    let tls_certs = load_certs(&std::env::var("TLS_CERTS_PATH").expect("TLS_CERTS_PATH required"))?;
    let tls_key = load_private_key(&std::env::var("TLS_KEY_PATH").expect("TLS_KEY_PATH required"))?;

    // Upstream Celestia HTTP(S) client
    let https_builder = HttpsConnectorBuilder::new().with_native_roots()?;
    let https_or_http_connector = if std::env::var("UNSAFE_HTTP_UPSTREAM").is_ok() {
        warn!("UNSAFE_HTTP_UPSTREAM set — allowing HTTP for upstream Celestia connection!");
        https_builder.https_or_http().enable_http1().build()
    } else {
        info!("UNSAFE_HTTP_UPSTREAM unset — forcing HTTPS for upstream connections");
        https_builder.https_only().enable_http1().build()
    };
    let da_http: HyperClient<_, StreamBody> =
        HyperClient::builder(TokioExecutor::new()).build(https_or_http_connector);

    // PDA Proxy TLS listener
    let listener = TcpListener::bind(service_socket).await?;
    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(tls_certs, tls_key)?;
    server_config.alpn_protocols = vec![b"http/1.1".to_vec(), b"http/1.0".to_vec()];
    let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));

    // Proof Runner setup
    let zk_proof_auction_timeout_remote = Duration::from_secs(
        std::env::var("PROOF_AUCTION_TIMEOUT_SECONDS_REMOTE")
            .expect("PROOF_AUCTION_TIMEOUT_SECONDS_REMOTE required")
            .parse()
            .expect("PROOF_AUCTION_TIMEOUT_SECONDS_REMOTE must be integer"),
    );
    let zk_proof_gen_timeout_remote = Duration::from_secs(
        std::env::var("PROOF_GEN_TIMEOUT_SECONDS_REMOTE")
            .expect("PROOF_GEN_TIMEOUT_SECONDS_REMOTE required")
            .parse()
            .expect("PROOF_GEN_TIMEOUT_SECONDS_REMOTE must be integer"),
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

    // Warm ZK clients
    tokio::spawn({
        let runner = pda_runner.clone();
        async move {
            let program_id = get_program_id().await;
            let zk_local = runner.clone().get_zk_client_local().await;
            let zk_remote = runner.clone().get_zk_client_remote().await;
            let _ = runner.get_proof_setup_local(&program_id, zk_local).await;
            let _ = runner.get_proof_setup_remote(&program_id, zk_remote).await;
            info!("ZK clients ready!");
        }
    });

    // Shutdown hook
    let (stop_tx, mut stop_rx) = tokio::sync::watch::channel::<bool>(false);
    tokio::spawn({
        let runner = pda_runner.clone();
        let stop_tx = stop_tx.clone();
        async move {
            wait_shutdown_signals().await;
            runner.shutdown();
            let _ = stop_tx.send(true);
        }
    });

    // Job Runner
    tokio::spawn({
        let runner = pda_runner.clone();
        async move { runner.job_worker(job_receiver).await }
    });

    // Restart pending jobs
    debug!("Restarting unfinished jobs");
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

    // DA client (submit mode)
    let mut builder = CelClient::builder()
        .rpc_url(&node_rpc_uri.to_string())
        .grpc_url(&core_grpc_uri)
        .private_key(&signer_key);

    if let Some(ref token) = node_write_token {
        builder = builder.rpc_auth_token(token);
    }

    let celestia_client_handle = Arc::new(
        builder
            .build()
            .await
            .expect("failed to build Celestia client"),
    );
    info!("Celestia client (submit mode) ready!");

    // --- Start serving ---
    info!("Listening on https://{service_socket}");

    loop {
        tokio::select! {
            _ = stop_rx.changed() => {
                info!("Shutdown signal received — stopping listener accept loop");
                break;
            }
            accept_res = listener.accept() => {
                let (stream, peer) = match accept_res {
                    Ok(t) => t,
                    Err(e) => {
                        error!("Accept failed: {e:?}");
                        continue;
                    }
                };

                let tls_acceptor = tls_acceptor.clone();
                let runner = pda_runner.clone();
                let da_http = da_http.clone();
                let cel_client = celestia_client_handle.clone();

                tokio::spawn(async move {
                    match tls_acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            let io = TokioIo::new(tls_stream);

                            let service = service_fn(move |req: Request<IncomingBody>| {
                                let runner = runner.clone();
                                let da_http = da_http.clone();
                                let da_client = cel_client.clone();

                                async move {
                                    // Fully buffer the JSON-RPC request so we can read the method
                                    let (parts, body_stream) = req.into_parts();
                                    let collected = match body_stream.collect().await {
                                        Ok(c) => c,
                                        Err(e) => {
                                            return Ok::<_, std::convert::Infallible>(
                                                internal_error_response(&format!("Read request body: {e}")),
                                            );
                                        }
                                    };
                                    let mut buf = collected.aggregate();
                                    let body_bytes = buf.copy_to_bytes(buf.remaining());

                                    let body_json: Value = match serde_json::from_slice(&body_bytes) {
                                        Ok(v) => v,
                                        Err(e) => {
                                            return Ok::<_, std::convert::Infallible>(
                                                internal_error_response(&format!("Invalid JSON-RPC: {e}")),
                                            );
                                        }
                                    };

                                    let method = body_json
                                        .get("method")
                                        .and_then(|m| m.as_str())
                                        .unwrap_or("")
                                        .to_owned();

                                    if method == "blob.Submit" {
                                        let blobs = match parse_submit_blobs(body_json) {
                                            Ok(ok) => ok,
                                            Err(e) => {
                                                return Ok::<_, std::convert::Infallible>(
                                                    bad_request_response(&format!("{e}")),
                                                );
                                            }
                                        };

                                        // Encrypt each blob via ZK job; if any pending, return 202
                                        let mut encrypted_blobs = Vec::with_capacity(blobs.len());
                                        for blob in blobs {
                                            let data = blob.data.clone();
                                            let job = Job {
                                                anchor: Anchor {
                                                    data: Sha256::digest(&data).as_slice().into(),
                                                },
                                                input: Input { data },
                                            };

                                            match runner.get_verifiable_encryption(job).await {
                                                Ok(Some(pwv)) => {
                                                    let enc = match bincode::serialize(&pwv) {
                                                        Ok(b) => b,
                                                        Err(e) => {
                                                            return Ok::<_, std::convert::Infallible>(
                                                                internal_error_response(&format!(
                                                                    "serialize proof: {e}"
                                                                )),
                                                            );
                                                        }
                                                    };
                                                    let b = match Blob::new(
                                                        blob.namespace,
                                                        enc,
                                                        blob.signer,
                                                        AppVersion::latest(),
                                                    ) {
                                                        Ok(b) => b,
                                                        Err(e) => {
                                                            return Ok::<_, std::convert::Infallible>(
                                                                internal_error_response(&format!(
                                                                    "Blob::new failed: {e}"
                                                                )),
                                                            );
                                                        }
                                                    };
                                                    encrypted_blobs.push(b);
                                                }
                                                Ok(None) => {
                                                    return Ok::<_, std::convert::Infallible>(
                                                        pending_response(),
                                                    );
                                                }
                                                Err(e) => {
                                                    return Ok::<_, std::convert::Infallible>(
                                                        internal_error_response(&format!(
                                                            "proof generation: {e}"
                                                        )),
                                                    );
                                                }
                                            }
                                        }

                                        match da_client
                                            .blob()
                                            .submit(&encrypted_blobs, TxConfig::default())
                                            .await
                                        {
                                            Ok(tx) => {
                                                let body = json!({
                                                    "id": 1,
                                                    "jsonrpc": "2.0",
                                                    "result": tx,
                                                });
                                                return Ok::<_, std::convert::Infallible>(json_response(
                                                    body,
                                                    StatusCode::OK,
                                                ));
                                            }
                                            Err(e) => {
                                                return Ok::<_, std::convert::Infallible>(
                                                    internal_error_response(&format!(
                                                        "Blob submit failed: {e}"
                                                    )),
                                                );
                                            }
                                        }
                                    }

                                    // Not Submit: forward upstream
                                    let req = rebuild_req(parts, &body_bytes, &node_rpc_uri);
                                    let resp =
                                        forward_then_maybe_decrypt(da_http, method, req, runner).await;

                                    Ok::<_, std::convert::Infallible>(resp)
                                }
                            });

                            if let Err(err) = http1::Builder::new()
                                .keep_alive(false) // ensure curl sees EOF even without Content-Length
                                .serve_connection(io, service)
                                .await
                            {
                                error!("Failed to serve connection from {peer:?}: {err:?}");
                            }
                        }
                        Err(e) => error!("TLS handshake failed: {e:?}"),
                    }
                });
            }
        }
    }

    Ok(())
}

/// Streaming body handling of responses, only buffered if needed.
async fn forward_then_maybe_decrypt(
    da_http: HyperClient<
        impl hyper_util::client::legacy::connect::Connect + Clone + Send + Sync + 'static,
        StreamBody,
    >,
    method: String,
    req: Request<StreamBody>,
    runner: Arc<PdaRunner>,
) -> Response<StreamBody> {
    match da_http.request(req).await {
        Ok(resp) => {
            if method == "blob.Get" || method == "blob.GetAll" {
                // Buffer only these to decrypt & rewrite
                match outbound_handler(resp, method, runner).await {
                    Ok(ok) => ok,
                    Err(e) => internal_error_response(&format!("Outbound Handler: {e}")),
                }
            } else {
                // Stream pass-through
                let (parts, body) = resp.into_parts();
                let body: StreamBody = body.boxed();
                Response::from_parts(parts, body)
            }
        }
        Err(e) => {
            warn!("DA Client connection failed: {e:?}");
            internal_error_response(&format!("DA Client: {e}"))
        }
    }
}

/// A hook to fix (modified) requests and point them to an upstream DA Node (JSON RPC)
fn rebuild_req(
    mut parts: http::request::Parts,
    body_bytes: &Bytes,
    upstream: &Uri,
) -> Request<StreamBody> {
    // Always target the upstream root "/"
    parts.uri = upstream.clone();

    // Ensure Host matches upstream (TLS/SNI & many RPC servers require it)
    if let Some(auth) = upstream.authority() {
        parts.headers.remove(HOST);
        parts
            .headers
            .insert(HOST, http::HeaderValue::from_str(auth.as_str()).unwrap());
    }

    // Let hyper recalc the length
    parts.headers.remove("content-length");

    let full = Full::new(body_bytes.clone())
        .map_err(|_: std::convert::Infallible| -> HyperError { unreachable!() })
        .boxed();
    Request::from_parts(parts, full)
}

/// Examine an outbound response; for blob.Get / blob.GetAll, verify/decrypt and rewrite.
/// Otherwise the caller streams pass-through.
async fn outbound_handler(
    resp: Response<IncomingBody>,
    request_method: String,
    pda_runner: Arc<PdaRunner>,
) -> Result<Response<StreamBody>> {
    let (mut parts, body_stream) = resp.into_parts();
    let collected = body_stream.collect().await?;
    let mut agg = collected.aggregate();
    let body_bytes = agg.copy_to_bytes(agg.remaining());

    let status = parts.status;
    if status == StatusCode::UNAUTHORIZED {
        return Ok(bad_auth_response());
    }

    // If response body isn't JSON, just pass it through
    let Ok(mut body_json): Result<Value, _> = serde_json::from_slice(&body_bytes) else {
        let orig_body: StreamBody = Full::new(body_bytes)
            .map_err(|_: std::convert::Infallible| -> HyperError { unreachable!() })
            .boxed();
        return Ok(Response::from_parts(parts, orig_body));
    };

    let try_mutate = async {
        let result_raw = body_json
            .get_mut("result")
            .ok_or_else(|| anyhow::anyhow!("Missing 'result' field"))?;

        let key =
            <[u8; 32]>::from_hex(std::env::var("ENCRYPTION_KEY").expect("Missing ENCRYPTION_KEY"))
                .expect("ENCRYPTION_KEY must be 32 bytes hex");

        match request_method.as_str() {
            "blob.Get" => {
                let blob: Blob = serde_json::from_value(result_raw.clone())?;
                let plain = verify_decrypt_blob(blob, key, pda_runner.clone()).await?;
                *result_raw = serde_json::to_value(plain)?;
            }
            "blob.GetAll" => {
                let arr = result_raw
                    .as_array()
                    .ok_or_else(|| anyhow::anyhow!("'result' is not array"))?
                    .clone();

                let mut out = Vec::with_capacity(arr.len());
                for b in arr {
                    let blob: Blob = serde_json::from_value(b)?;
                    let plain = verify_decrypt_blob(blob, key, pda_runner.clone()).await?;
                    out.push(serde_json::to_value(plain)?);
                }
                *result_raw = Value::Array(out);
            }
            _ => { /* shouldn't happen here */ }
        }

        Ok::<(), anyhow::Error>(())
    }
    .await;

    if let Err(err) = try_mutate {
        warn!("Failed to decrypt response: {err:?}");
        let orig_body: StreamBody = Full::new(body_bytes)
            .map_err(|_: std::convert::Infallible| -> HyperError { unreachable!() })
            .boxed();
        return Ok(Response::from_parts(parts, orig_body));
    }

    // We're replacing the body with a fixed buffer; drop any hop-by-hop length hints.
    parts.headers.remove("content-length");
    parts.headers.remove(hyper::header::TRANSFER_ENCODING);

    let new_body: StreamBody = Full::new(Bytes::from(serde_json::to_vec(&body_json)?))
        .map_err(|_: std::convert::Infallible| -> HyperError { unreachable!() })
        .boxed();
    Ok(Response::from_parts(parts, new_body))
}

/// Verify a proof before decrypting the contained blob data
async fn verify_decrypt_blob(
    mut blob: Blob,
    key: [u8; 32],
    pda_runner: Arc<PdaRunner>,
) -> Result<Blob, anyhow::Error> {
    let proof: SP1ProofWithPublicValues = bincode::deserialize(&blob.data)?;
    let output = {
        let proof: &SP1ProofWithPublicValues = &proof;
        async move {
            let zk_client_local = pda_runner.get_zk_client_local().await;
            let vk = &pda_runner
                .get_proof_setup_local(&get_program_id().await, zk_client_local.clone())
                .await?
                .vk;
            zk_client_local.verify(proof, vk)?;
            ZkvmOutput::from_bytes(proof.public_values.as_slice()).map_err(anyhow::Error::msg)
        }
    }
    .await?;
    let mut buffer = output.ciphertext.to_owned();
    chacha(&key, &output.nonce, &mut buffer);
    blob.data = buffer.to_vec();
    Ok(blob)
}

/// Helper: throw JSON error is blob.Submit can't be parsed
fn parse_submit_blobs(mut body_json: Value) -> anyhow::Result<Vec<Blob>> {
    let params_raw = body_json
        .get_mut("params")
        .ok_or_else(|| anyhow::anyhow!("missing params"))?;

    let arr = params_raw
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("`params` must be an array"))?;

    if arr.is_empty() {
        return Err(anyhow::anyhow!("`params` array is empty"));
    }

    let blobs_value = arr
        .get_mut(0)
        .ok_or_else(|| anyhow::anyhow!("missing blobs param at index 0"))?;

    let blobs: Vec<Blob> = serde_json::from_value(std::mem::take(blobs_value))
        .map_err(|e| anyhow::anyhow!("invalid blobs array: {e}"))?;

    Ok(blobs)
}
