#!/bin/bash
# Workflow 3 proof: the payments user can read only the payments secret, and only
# through the payments socket. The analytics user cannot open that socket.
# Sending the dev root token on the payments socket does not widen it, because
# the agent forces its TPM-minted auto-auth token.
set -euo pipefail
STAGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${STAGE_DIR}/common.sh"

RUN_DIR="/run/vault-proxy"
STATE_ROOT="/var/lib/vault-agent"

require_cmd vault runuser stat || die "missing prerequisites"
[[ -S "${RUN_DIR}/payments.sock" ]] || die "no payments socket — run 'task proxies' first"
[[ -S "${RUN_DIR}/analytics.sock" ]] || die "no analytics socket — run 'task proxies' first"

# Sets CALL_RC and CALL_OUT. Does not source the lab env: that file holds the
# dev root token, and these calls must be the application user with only the
# socket.
CALL_RC=0
CALL_OUT=''
as_app() {
  local user="$1" addr="$2"
  shift 2
  local rc=0 out
  out="$(runuser -u "${user}" -- env -u VAULT_TOKEN "VAULT_ADDR=${addr}" "$@" 2>&1)" || rc=$?
  CALL_RC="${rc}"
  CALL_OUT="${out}"
}

log_step "Workflow 3: per-app Unix-socket isolation"

log_info "1. payments, through its own socket, reads its own secret."
as_app payments "unix://${RUN_DIR}/payments.sock" \
  vault kv get -field=message secret/payments/app
if (( CALL_RC == 0 )); then
  report_expect "payments settlement batch" "${CALL_OUT}"
else
  report_expect "payments settlement batch" "read FAILED: ${CALL_OUT}"
  die "the payments agent could not read the payments secret"
fi

log_info ""
log_info "2. The same socket is refused the analytics secret."
as_app payments "unix://${RUN_DIR}/payments.sock" \
  vault kv get -field=message secret/analytics/app
if (( CALL_RC != 0 )) && printf '%s' "${CALL_OUT}" | grep -qi 'permission denied' \
  && ! printf '%s' "${CALL_OUT}" | grep -q 'dial unix'; then
  report_expect "permission denied by payments-read" "permission denied"
else
  report_expect "permission denied by payments-read" "${CALL_OUT}"
  die "the payments agent was not kept out of the analytics secret"
fi

log_info ""
log_info "3. Putting the dev root token on that request does not change the result."
rc=0
out="$(runuser -u payments -- env VAULT_TOKEN=root "VAULT_ADDR=unix://${RUN_DIR}/payments.sock" \
  vault kv get -field=message secret/analytics/app 2>&1)" || rc=$?
if (( rc != 0 )) && printf '%s' "${out}" | grep -qi 'permission denied'; then
  report_expect "agent forces the payments TPM token" "permission denied (client token ignored)"
else
  report_expect "agent forces the payments TPM token" "${out}"
  die "the payments socket honoured a client-supplied token"
fi

log_info ""
log_info "4. analytics cannot open the payments socket."
as_app analytics "unix://${RUN_DIR}/payments.sock" \
  vault kv get -field=message secret/payments/app
if (( CALL_RC != 0 )) && printf '%s' "${CALL_OUT}" | grep -q 'dial unix' \
  && printf '%s' "${CALL_OUT}" | grep -qi 'permission denied'; then
  report_expect "socket connect refused" "permission denied"
else
  report_expect "socket connect refused" "${CALL_OUT}"
  die "the analytics user reached the payments socket"
fi

log_info ""
log_info "5. analytics, through its own socket, reads its own secret."
as_app analytics "unix://${RUN_DIR}/analytics.sock" \
  vault kv get -field=message secret/analytics/app
if (( CALL_RC == 0 )); then
  report_expect "analytics risk model" "${CALL_OUT}"
else
  report_expect "analytics risk model" "read FAILED: ${CALL_OUT}"
  die "the analytics agent could not read the analytics secret"
fi

log_info ""
log_info "6. payments cannot open the analytics socket or the TPM attestation state."
as_app payments "unix://${RUN_DIR}/analytics.sock" \
  vault kv get -field=message secret/analytics/app
socket_denied=0
if (( CALL_RC != 0 )) && printf '%s' "${CALL_OUT}" | grep -q 'dial unix'; then
  socket_denied=1
fi
state_rc=0
runuser -u payments -- ls "${STATE_ROOT}/payments/tpm" >/dev/null 2>&1 || state_rc=$?
other_rc=0
runuser -u payments -- ls "${STATE_ROOT}/analytics/tpm" >/dev/null 2>&1 || other_rc=$?
if (( socket_denied == 1 && state_rc != 0 && other_rc != 0 )); then
  report_expect "analytics socket and TPM state dirs refused" "all refused"
else
  report_expect "analytics socket and TPM state dirs refused" \
    "socket_denied=${socket_denied} payments_state_rc=${state_rc} analytics_state_rc=${other_rc}"
  die "payments can still reach something that bypasses its socket"
fi

log_info ""
log_ok "each user reaches only the agent whose socket they own, and that agent is one TPM role"
