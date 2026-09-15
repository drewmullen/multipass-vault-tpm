#!/bin/bash
# Bonus: two applications on one host, one generic cert-auth credential.
#
# payments-app may read secret/payments/app and nothing else.
# analytics-app may read secret/analytics/app and nothing else.
# Both cert roles trust the same device CA and the same common name, so
# node01's TPM key and certificate satisfy either login. The role name is a
# field in the login body. This script shows that the policy boundary holds
# for a token, and that it does not hold between the two applications, because
# whichever one can drive the TPM can name the other role.
set -euo pipefail
STAGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${STAGE_DIR}/common.sh"

device="${1:-node01}"
PAYMENTS_PATH="secret/payments/app"
ANALYTICS_PATH="secret/analytics/app"

require_cmd jq || die "missing prerequisites"
[[ -f "${LAB_PKI_DIR}/${device}.crt" ]] || die "no certificate for ${device} — run 'task enrol' first"
[[ -f "${LAB_PKI_DIR}/${device}.tpmkey.pem" ]] || die "no TPM key for ${device} — run 'task enrol' first"

# 50_login.sh overwrites state/login.json with whichever role it just used.
# Put the original device token back so a later 'task demo:privilege' still
# finds the token it expects.
restore_device_login() {
  local rc=0
  bash "${STAGE_DIR}/50_login.sh" "${device}" --role tpm-devices --quiet-json >/dev/null || rc=$?
  if (( rc != 0 )); then
    log_warn "could not restore the ${device} device login; re-run 'task demo:login' before 'task demo:privilege'"
  fi
}
trap restore_device_login EXIT

# Login with the enrolled TPM certificate. The role is the only thing that
# changes between the two applications. Prints the client token, or empty on
# failure. Login noise stays on stderr.
login_token() {
  local role="$1" json rc=0 token
  json="$(bash "${STAGE_DIR}/50_login.sh" "${device}" --role "${role}" --quiet-json)" || rc=$?
  if (( rc != 0 )); then
    return "${rc}"
  fi
  token="$(printf '%s' "${json}" | jq -r '.auth.client_token // empty')"
  printf '%s' "${token}"
  [[ -n "${token}" ]]
}

# kv get as a particular token. Sets READ_RC, READ_OUT and READ_MESSAGE.
# Vault's 403 is several lines; "permission denied" is not on the first.
READ_RC=0
READ_OUT=''
READ_MESSAGE=''
read_secret() {
  local token="$1" path="$2" out rc=0
  out="$(as_lab_user_allow_fail env "VAULT_TOKEN=${token}" vault kv get -format=json "${path}" 2>&1)" || rc=$?
  READ_RC="${rc}"
  READ_OUT="${out}"
  if (( rc == 0 )); then
    READ_MESSAGE="$(printf '%s' "${out}" | jq -r '.data.data.message // "(no message field)"')"
  else
    READ_MESSAGE="$(printf '%s\n' "${out}" | grep -m1 -v '^[[:space:]]*$' || printf '(no output)')"
  fi
}

log_step "Bonus: shared certificate cannot isolate two applications"

log_info "payments-app may read ${PAYMENTS_PATH}."
log_info "analytics-app may read ${ANALYTICS_PATH}."
log_info "Both roles accept ${device}'s certificate. The login body names the role."
log_info ""

log_info "1. The payments application logs in as payments-app and stays inside its policy."
payments_token="$(login_token payments-app)" || die "payments-app login failed — run 'task config' so the role exists, then 'task enrol'"
log_detail "   authenticated with ${device}'s TPM key, role payments-app"

read_secret "${payments_token}" "${PAYMENTS_PATH}"
if (( READ_RC == 0 )); then
  report_expect "payments secret readable" "read succeeded: \"${READ_MESSAGE}\""
else
  report_expect "payments secret readable" "read FAILED: ${READ_MESSAGE}"
  die "payments-app could not read its own secret — the role or the policy is not what Part 5.6 wrote"
fi

read_secret "${payments_token}" "${ANALYTICS_PATH}"
if (( READ_RC != 0 )) && printf '%s' "${READ_OUT}" | grep -qi 'permission denied'; then
  report_expect "analytics secret denied to this token" "permission denied"
else
  report_expect "analytics secret denied to this token" "boundary missing: ${READ_MESSAGE}"
  die "the payments-app token could read the analytics secret — the policies are not separate"
fi

log_info ""
log_info "2. The same TPM key logs in as analytics-app. Only the role name changes."
analytics_rc=0
analytics_token="$(login_token analytics-app)" || analytics_rc=$?

if (( analytics_rc != 0 )) || [[ -z "${analytics_token}" ]]; then
  report_expect "same TPM certificate refused for analytics-app" \
                "login failed (rc=${analytics_rc}) — this host could not take the other role"
  log_ok "the role name was not enough; the second login was refused"
  exit 0
fi

read_secret "${analytics_token}" "${ANALYTICS_PATH}"
log_info ""
if (( READ_RC == 0 )); then
  report_expect "analytics secret stays unreadable without a separate credential" \
                "same TPM certificate, role analytics-app, read succeeded: \"${READ_MESSAGE}\""
else
  report_expect "analytics secret stays unreadable without a separate credential" \
                "login succeeded but the read failed: ${READ_MESSAGE}"
fi

log_info ""
log_info "The token from step 1 could not read the analytics secret. The caller could,"
log_info "by asking Vault for the other role with the same TPM-held key. The policy"
log_info "splits the secrets. The TPM does not split the applications."
