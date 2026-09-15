#!/bin/bash
# Workflow 1: native Vault TPM authentication from the machine CLI.
# The operator sees certificate acquisition, login, token policy and one read.
set -euo pipefail
STAGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${STAGE_DIR}/common.sh"

device="${1:-node01}"
domain="${2:-devices.lab.local}"
role="machine-cli"
state_dir="/var/lib/vault-agent/cli/tpm"
secret_path="secret/devices/${device}"

require_cmd vault jq systemctl || die "missing prerequisites"
[[ -S "${SWTPM_UNIX_SOCK}" ]] || die "no ${SWTPM_UNIX_SOCK} — run 'task tpm' first"
as_lab_user_allow_fail vault read "auth/tpm/role/${role}" >/dev/null 2>&1 \
  || die "auth/tpm/role/${role} missing — run 'task config' first"

log_step "Workflow 1: direct TPM login from the machine"
log_info "The CLI performs TPM attestation once, then uses the resulting"
log_info "role-bound certificate and TPM key to request a Vault token."

# Other TPM clients can consume swtpm's small transient-object pool. This
# workflow is deliberately the only client while its key is acquired.
systemctl stop vault-proxy-single vault-proxy@payments vault-proxy@analytics \
  >/dev/null 2>&1 || true
systemctl restart swtpm@device
wait_for_unit swtpm@device 30 || die "swtpm@device did not recover"
systemctl restart swtpm-unix-bridge
wait_for_unit swtpm-unix-bridge 15 || die "swtpm-unix-bridge did not recover"
as_lab_user tpm2_dictionarylockout -c || true
install -d -m 0700 "${state_dir}"
find "${state_dir}" -mindepth 1 -type f -delete 2>/dev/null || true

log_info ""
log_info "1. Acquire a role-bound certificate by attesting the TPM."
log_detail "$ vault tpm attest -role-name=${role} \\"
log_detail "    -tpm-device-path=${SWTPM_UNIX_SOCK} \\"
log_detail "    -tpm-state-dir=${state_dir} \\"
log_detail "    -cert-subject-CN=${device}.${domain}"
env -u VAULT_TOKEN \
  "VAULT_ADDR=https://127.0.0.1:8200" \
  "VAULT_CACERT=${LAB_TLS_DIR}/vault-ca.pem" \
  vault tpm attest \
    -role-name="${role}" \
    -tpm-device-path="${SWTPM_UNIX_SOCK}" \
    -tpm-state-dir="${state_dir}" \
    -cert-subject-CN="${device}.${domain}"
log_ok "Vault attested the TPM and issued the ${role} certificate"

log_info ""
log_info "2. Log in with the TPM-backed certificate."
log_detail "$ vault login -method=tpm -no-store \\"
log_detail "    -tpm-state-dir=${state_dir} \\"
log_detail "    -tpm-device-path=${SWTPM_UNIX_SOCK} role_name=${role}"
login_rc=0
login_raw="$(
  env -u VAULT_TOKEN \
    "VAULT_ADDR=https://127.0.0.1:8200" \
    "VAULT_CACERT=${LAB_TLS_DIR}/vault-ca.pem" \
    vault login -method=tpm -no-store -format=json \
      -tpm-state-dir="${state_dir}" \
      -tpm-device-path="${SWTPM_UNIX_SOCK}" \
      role_name="${role}" 2>&1
)" || login_rc=$?
if (( login_rc != 0 )); then
  printf '%s\n' "${login_raw}"
  die "native TPM login failed"
fi

# -no-store emits a reminder before the requested JSON.
login_json="$(printf '%s\n' "${login_raw}" | sed -n '/^{/,$p')"
token="$(printf '%s' "${login_json}" | jq -r '.auth.client_token // empty')"
policies="$(printf '%s' "${login_json}" | jq -r '(.auth.token_policies // .auth.policies // []) | join(", ")')"
login_role="$(printf '%s' "${login_json}" | jq -r '.auth.metadata.role_name // "(none)"')"
[[ -n "${token}" ]] || die "native TPM login returned no token"
log_ok "Vault returned a token for role ${login_role}"
log_detail "   policies: ${policies}"
log_detail "   token: ${token:0:12}... (${#token} chars)"

log_info ""
log_info "3. Use the CLI-managed token to read its permitted secret."
log_detail "$ VAULT_TOKEN=<machine-cli> vault kv get -field=message ${secret_path}"
message="$(
  as_lab_user env "VAULT_TOKEN=${token}" \
    vault kv get -field=message "${secret_path}"
)"
printf '%s\n' "${message}"

as_lab_user vault token revoke "${token}" >/dev/null \
  || log_warn "could not revoke the demonstration token"
log_ok "direct login succeeded; the CLI received and managed the token"
