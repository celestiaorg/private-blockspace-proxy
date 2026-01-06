#  Base with Rust, Go, CUDA, SP1, and cargo-chef
FROM nvidia/cuda:12.9.1-devel-ubuntu24.04 AS base-dev

RUN apt-get update && DEBIAN_FRONTEND=noninteractive \
    apt-get install --no-install-recommends -y \
    clang libclang-dev docker.io curl tar build-essential pkg-config git ca-certificates gnupg2 \
    && rm -rf /var/lib/apt/lists/*
 
ENV GO_VERSION=1.24.5
ENV GO_URL="https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
RUN curl -L --proto '=https' --tlsv1.2 -sSf ${GO_URL} -o go.tar.gz && \
    mkdir -p /opt/go && \
    tar -C /opt/go --strip-components=1 -xzf go.tar.gz && \
    rm go.tar.gz
ENV PATH="/opt/go/bin:${PATH}"

# Ensure we cache toolchain & components
WORKDIR /app
COPY ./rust-toolchain.toml ./

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# https://github.com/LukeMathWalker/cargo-chef/
RUN cargo install cargo-chef

# https://docs.succinct.xyz/docs/sp1/getting-started/install
RUN curl -L https://sp1up.succinct.xyz | bash && \
    /root/.sp1/bin/sp1up

####################################################################################################
FROM base-dev AS planner

WORKDIR /app

COPY . .

RUN cargo chef prepare --recipe-path recipe.json

####################################################################################################
FROM base-dev AS builder

WORKDIR /app
COPY --from=planner /app/recipe.json ./

RUN --mount=type=cache,id=target_cache,target=/app/target \
    cargo chef cook --release --recipe-path recipe.json

COPY . .

# Build SP1 ELF to be proven (with optimizations)
# WARNING: we do NOT assume `cargo prove build --docker` is required for identical ELF
RUN --mount=type=cache,id=target_cache,target=/app/target \
    RUSTFLAGS="-Copt-level=3 -Clto=fat -Ccodegen-units=1 -Cdebuginfo=1 -Cembed-bitcode=yes"\
    /root/.sp1/bin/cargo-prove prove build -p chacha-program
# Build the final binary, embbeding ELF
RUN --mount=type=cache,id=target_cache,target=/app/target \
    cargo build --release && \
    strip /app/target/release/pbs-proxy && \
    cp target/release/pbs-proxy /app/pbs-proxy # pop out of cache

####################################################################################################
FROM nvidia/cuda:12.9.1-base-ubuntu24.04 AS runtime

# SP1 CUDA support needs Docker-in-Docker to run `moongate-server` prover service
# Internally run on localhost:3000
COPY --from=base-dev /usr/bin/docker /usr/bin/docker
COPY --from=builder /app/pbs-proxy /usr/local/bin/pbs-proxy

ENTRYPOINT ["/usr/local/bin/pbs-proxy"]
