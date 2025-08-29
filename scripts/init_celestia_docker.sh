#!/bin/bash

# Helper to init a Celestia node

set -euo pipefail

source ../.env
source ./common.sh

# === FUNCTIONS ===

pull_image() {
  echo "🚀 Pulling $CELESTIA_DOCKER_IMAGE image..."
  docker pull "$CELESTIA_DOCKER_IMAGE"
}

initialize_node() {
  mkdir -p "$CELESTIA_DATA_DIR"
  if [ ! -f "$CELESTIA_DATA_DIR/config.toml" ]; then
    echo "🔧 Initializing $CELESTIA_NODE_TYPE node for $CELESTIA_NETWORK network..."
    docker run --rm \
      --user $(id -u):$(id -g) \
      -v "$CELESTIA_DATA_DIR:/home/celestia" \
      "$CELESTIA_DOCKER_IMAGE" \
      /bin/celestia "$CELESTIA_NODE_TYPE" init --core.ip "$CELESTIA_CORE_IP" --p2p.network "$CELESTIA_NETWORK"
      # NOTE: we need to be sure the user on the HOST owns these
      echo "NOTE: HOST user (${USER}) must own $CELESTIA_DATA_DIR created by root, so we use sudo:"
      sudo chown -R $USER:$USER $CELESTIA_DATA_DIR
  else
    echo "✅ Node already initialized at $CELESTIA_DATA_DIR"
  fi
}

set_write_jwt_with_docker() {
  local token_output
  token_output=$(docker run --rm \
    --user $(id -u):$(id -g) \
    -v "$CELESTIA_DATA_DIR:/home/celestia" \
    "$CELESTIA_DOCKER_IMAGE" \
    /bin/celestia "$CELESTIA_NODE_TYPE" auth write 2>&1)

  # Check for Docker run failure
  if [[ $? -ne 0 ]]; then
    echo "❌ Error running docker container:"
    echo "$token_output"
    return 1
  fi

  # Trim logs, only keep last line (the actual token)
  export CELESTIA_NODE_WRITE_TOKEN=$(echo "$token_output" | tail -n 1)

  update_env_var "CELESTIA_NODE_WRITE_TOKEN" "${CELESTIA_NODE_WRITE_TOKEN}"
}

# We assume no trusted hash means we want to update to whatever the latest block is
update_latest_block_trusted_hash() {
  read_toml_to_export_var "Header.TrustedHash" "CELESTIA_TRUSTED_HASH" "${CELESTIA_DATA_DIR}/config.toml"

  if [[ -z "$CELESTIA_TRUSTED_HASH" ]]; then
    echo "Setting Trusted Hash and block sync to most recent block from ${CELESTIA_CORE_IP}"
    local header_json
    header_json=$(curl -s "https://${CELESTIA_CORE_IP}/header")

    export CELESTIA_TRUSTED_HEIGHT=$(echo "$header_json" | jq -r '.result.header.height')
    export CELESTIA_TRUSTED_HASH=$(echo "$header_json" | jq -r '.result.header.last_block_id.hash')
    echo "DASer.SampleFrom = $CELESTIA_TRUSTED_HEIGHT"
    echo "Header.TrustedHash = $CELESTIA_TRUSTED_HASH"

    update_toml_from_var "DASer.SampleFrom" "${CELESTIA_TRUSTED_HEIGHT}" "${CELESTIA_DATA_DIR}/config.toml"
    update_toml_from_var "Header.TrustedHash" "${CELESTIA_TRUSTED_HASH}" "${CELESTIA_DATA_DIR}/config.toml"
  else
    echo "Trusted Hash configured: ${CELESTIA_TRUSTED_HASH}"
  fi
}


# Unused but for reference:
# run_node() {
#   echo "🏃‍   Starting $CELESTIA_NODE_TYPE node on $CELESTIA_NETWORK network..."
#   docker run -d \
#     --name "$CELESTIA_NODE_NAME" \
#     -v "$CELESTIA_DATA_DIR:/home/celestia" \
#     -p "$CELESTIA_NODE_P2P_PORT:$CELESTIA_NODE_P2P_PORT" \
#     -p "$CELESTIA_RPC_PORT:$CELESTIA_RPC_PORT" \
#     "$CELESTIA_DOCKER_IMAGE" \
#     /bin/celestia "$CELESTIA_NODE_TYPE" start --core.ip "$CELESTIA_CORE_IP" --p2p.network "$CELESTIA_NETWORK"
# }

# === MAIN EXECUTION ===

pull_image
initialize_node
set_write_jwt_with_docker
update_latest_block_trusted_hash

echo "✅ Updated .env and ${CELESTIA_DATA_DIR}/config.toml"
echo -e "🎉 $CELESTIA_NODE_TYPE node for $CELESTIA_NETWORK network is ready with persistent storage at $CELESTIA_DATA_DIR"


