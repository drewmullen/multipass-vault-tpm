#!/bin/bash
# Workflow 2 proof: an ordinary HTTP client uses Vault through Agent without
# receiving or managing a Vault token. This is token automation, not isolation.
set -euo pipefail
STAGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${STAGE_DIR}/common.sh"

proxy_addr="http://127.0.0.1:8100"

require_cmd vault || die "missing prerequisites"

log_step "Workflow 2: workload uses a standard Vault URL"
log_info "The application sends an ordinary Vault request to ${proxy_addr}."
log_info "Vault Agent supplies and renews its payments-app token automatically."
log_info "This localhost listener is intentionally not a process-isolation boundary."

log_info ""
log_info "1. Read the workload's permitted secret without handling a token."
log_detail "$ VAULT_ADDR=${proxy_addr} VAULT_TOKEN=unused \\"
log_detail "    vault kv get -field=message secret/payments/app"
message="$(
  env "VAULT_ADDR=${proxy_addr}" VAULT_TOKEN=unused \
    vault kv get -field=message secret/payments/app
)"
printf '%s\n' "${message}"

log_info ""
log_info "2. A caller-supplied root token cannot widen the proxy."
log_detail "$ VAULT_ADDR=${proxy_addr} VAULT_TOKEN=root \\"
log_detail "    vault kv get -field=message secret/analytics/app"
rc=0
out="$(
  env "VAULT_ADDR=${proxy_addr}" VAULT_TOKEN=root \
    vault kv get -field=message secret/analytics/app 2>&1
)" || rc=$?
if (( rc != 0 )) && printf '%s' "${out}" | grep -qi 'permission denied'; then
  printf '%s\n' "permission denied (caller token ignored)"
else
  printf '%s\n' "${out}"
  die "the HTTP proxy honoured a caller-supplied token"
fi

log_ok "the workload uses a normal URL while Agent owns the token lifecycle"
