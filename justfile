default:
    @just --list

alias r := run-debug
alias rr := run-release
alias rrr := run-release-reproducible
alias bc := bench-cycles
alias db := docker-build
alias ds := docker-save
alias dl := docker-load
alias dr := docker-run
alias b := build-debug
alias br := build-release
alias brr := build-release-reproducible
alias f := fmt
alias c := clean
alias cb := curl-blob-submit-with-max-gas

# Bash, fail with undefined vars

set shell := ["bash", "-cu"]
set quiet := true
set dotenv-path := ".env"

env-settings := ".env"

# SP1 just recipies
sp1 *args:
    @just --justfile ./zkVM/sp1/justfile {{ args }}

# Install SP1 tooling & more
initial-config-installs:
    @just sp1 initial-config-installs

_pre-build:
    @just sp1 build-elf

_pre-build-reproducible:
    @just sp1 build-elf-reproducible

_pre-run:
    echo "just pre-run TODO"

# Check cycle counts for zkVM on ./zkVM/static example inputs
bench-cycles *FLAGS: _pre-build _pre-run
    cargo r -r -p sp1-util --bin cli -- --execute

# Run in release mode, zkVM ELF stable with optimizations AND debug logs
run-release-reproducible *FLAGS: _pre-build-reproducible _pre-run
    RUST_LOG=pda_proxy=debug cargo r -r --features reproducible-elf -- {{ FLAGS }}

# Run in release mode, with optimizations AND debug logs
run-release *FLAGS: _pre-build _pre-run
    RUST_LOG=pda_proxy=debug cargo r -r -- {{ FLAGS }}

# Run in debug mode, with extra pre-checks, no optimizations
run-debug *FLAGS: _pre-build _pre-run
    # TODO :Check DA node up with some healthcheck endpoint
    RUST_LOG=pda_proxy=debug cargo r -- {{ FLAGS }}

# Build docker image & tag
docker-build:
    DOCKER_BUILDKIT=1 docker build \
      --build-arg BUILDKIT_INLINE_CACHE=1 \
      --tag "$DOCKER_CONTAINER_NAME" \
      --progress=plain \
      .

# Save docker image to a tar.gz
docker-save:
    docker save "$DOCKER_CONTAINER_NAME" | gzip > "/tmp/$DOCKER_CONTAINER_NAME-docker.tar.gz"

# Load docker image from tar.gz
docker-load:
    gunzip -c "/tmp/$DOCKER_CONTAINER_NAME-docker.tar.gz" | docker load

# Run a pre-built docker image
docker-run:
    mkdir -p $PDA_DB_PATH
    # Note socket assumes running "normally" with docker managed by root
    # TODO: support docker rootless!
    # FIXME: files with relative paths accross .env file!
    docker run --rm -it \
      -v /var/run/docker.sock:/var/run/docker.sock \
      -v ./service/static:/app/static \
      -v $HOME/.sp1/circuits:/root/.sp1/circuits \
      -v $PDA_DB_PATH:$PDA_DB_PATH \
      --env-file {{ env-settings }} \
      --env TLS_CERTS_PATH=/app/static/sample.pem \
      --env TLS_KEY_PATH=/app/static/sample.rsa \
      --env RUST_LOG=pda_proxy=debug \
      --network=host \
      -p $PDA_PORT:$PDA_PORT \
      $DOCKER_CONTAINER_NAME

# Build in debug mode, no optimizations
build-debug: _pre-build
    cargo b

# Build in release mode, includes optimizations
build-release: _pre-build
    cargo b -r

# Build in release mode, enforce ELF build is reproducible includes optimizations
build-release-reproducible: _pre-build-reproducible
    cargo b -r --features reproducible-elf

# Scrub build artifacts
clean:
    cargo clean

# Format source code (Rust, Justfile, and TOMLs)
fmt:
    cargo fmt # *.rs
    just --quiet --unstable --fmt > /dev/null # justfile
    taplo format > /dev/null 2>&1 # *.toml

# Build & open Rustdocs for the workspace
doc:
    RUSTDOCFLAGS="--enable-index-page -Zunstable-options" cargo +nightly doc --no-deps --workspace
    firefox {{ justfile_directory() }}/target/doc/index.html
    # TODO fix snadbox issues with flatpak
    # xdg-open {{ justfile_directory() }}/target/doc/index.html

# Launch a local Celestia testnet: Mocha
mocha:
    # Assumes you already did init for this & configured
    # If not, see https://docs.celestia.org/tutorials/node-tutorial#setting-up-dependencies
    celestia light start --core.ip rpc-mocha.pops.one --p2p.network mocha --rpc.skip-auth

# Setup and print to stdout, needs to be set in env to be picked up

# See also ./scripts/init_celestia_docker.sh
mocha-local-auth:
    celestia light auth admin --p2p.network mocha

# Check API is responsive, by using proxy (non-intercepted call)
celestia-node-healthcheck-proxy:
    curl -sf \
      -H "Content-Type: application/json" \
      -H "Authorization: Bearer ${CELESTIA_NODE_WRITE_TOKEN}" \
      --data '{"jsonrpc":"2.0","id":1,"method":"header.SyncState","params":[]}' \
      https://127.0.0.1:26657 \
      --insecure | jq

# Check API is responsive, required for proxy to function
celestia-node-healthcheck-direct:
    curl -sf \
      -H "Content-Type: application/json" \
      -H "Authorization: Bearer ${CELESTIA_NODE_WRITE_TOKEN}" \
      --data '{"jsonrpc":"2.0","id":1,"method":"header.SyncState","params":[]}' \
      $CELESTIA_NODE_RPC | jq

# Check balance for any address. NOTE: MUST be a known good address, i.e.: celestia1377k5an3f94v6wyaceu0cf4nq6gk2jtpc46g7h
celestia-node-balance-for ADDR:
    curl -sf \
      -H "Content-Type: application/json" \
      -H "Authorization: Bearer ${CELESTIA_NODE_WRITE_TOKEN}" \
      --data '{"jsonrpc":"2.0","id":1,"method":"state.BalanceForAddress","params":["{{ ADDR }}"]}' \
      http://127.0.0.1:26657 | jq

# Check balance for local node
celestia-node-balance:
    curl -sf \
      -H "Content-Type: application/json" \
      -H "Authorization: Bearer ${CELESTIA_NODE_WRITE_TOKEN}" \
      --data '{"jsonrpc":"2.0","id":1,"method":"state.Balance","params":[]}' \
      $CELESTIA_NODE_RPC | jq

# https://mocha-4.celenium.io/tx/28fa01d026ac5a229e5d5472a204d290beda02ea229f6b3f42da520b00154e58?tab=messages

# Test blob.Get for PDA Proxy
curl-blob-get:
    curl -H "Content-Type: application/json" -H "Authorization: Bearer $CELESTIA_NODE_WRITE_TOKEN" --data '{"id": 1,"jsonrpc": "2.0", "method": "blob.Get", "params": [ 6629478, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAMJ/xGlNMdE=", "yS3XX33mc1uXkGinkTCvS9oqE0k9mtHMWTz0mwZccOc=" ] }' \
    https://127.0.0.1:26657 \
    --insecure | jq

# https://mocha-4.celenium.io/tx/28fa01d026ac5a229e5d5472a204d290beda02ea229f6b3f42da520b00154e58?tab=messages

# Test blob.Get for local light node
curl-blob-get-passthrough:
    curl -H "Content-Type: application/json" -H "Authorization: Bearer $CELESTIA_NODE_WRITE_TOKEN" --data '{"id": 1,"jsonrpc": "2.0", "method": "blob.Get", "params": [ 6629478, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAMJ/xGlNMdE=", "yS3XX33mc1uXkGinkTCvS9oqE0k9mtHMWTz0mwZccOc=" ] }' \
    $CELESTIA_NODE_RPC | jq

# https://mocha.celenium.io/tx/436f223bfa8c4adf1e1b79dde43a84918f3a50809583c57c33c1c079568b47cb?tab=messages

# Test blob.Submit for PDA proxy, max gas price is minimum 0.0004utia
curl-blob-submit-with-max-gas:
    curl -H "Content-Type: application/json" \
         -H "Authorization: Bearer $CELESTIA_NODE_WRITE_TOKEN" \
         --data '{"id":1,"jsonrpc":"2.0","method":"blob.Submit","params":[[{"namespace":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAMJ/xGlNMdE=","data":"DEADB33F","share_version":0,"commitment":"aHlbp+J9yub6hw/uhK6dP8hBLR2mFy78XNRRdLf2794=","index":-1}],{"max_gas_price":0.010}]}' \
         https://127.0.0.1:26657 \
         --insecure | jq
