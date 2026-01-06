#!/usr/bin/env bash

# Helper to send a test file to the proxy with curl
# WARN: Hard coded incorrect variables here otherwise!

FILE="../zkVM/static/proof_input_example.bin"
source ../.env
{
  echo -n '{ "id": 1, "jsonrpc": "2.0", "method": "blob.Submit", "params": [ [ { "namespace": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAMJ/xGlNMdE=", "data": "'
  base64 -w0 "$FILE"
  echo '", "share_version": 0, "commitment": "aHlbp+J9yub6hw/uhK6dP8hBLR2mFy78XNRRdLf2794=", "index": -1 } ], {} ] }'
} | curl -H "Content-Type: application/json" -H "Authorization: Bearer $CELESTIA_NODE_WRITE_TOKEN" \
        --data @- https://$TLS_DOMAIN --verbose # remote on 443

# | curl -H "Content-Type: application/json" -H "Authorization: Bearer $CELESTIA_NODE_WRITE_TOKEN" \
#          --data @- https://$PBS_SOCKET --verbose --insecure # local
