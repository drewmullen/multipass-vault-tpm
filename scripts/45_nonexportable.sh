#!/bin/bash
# Non-exportability proof: the file on disk is a TPM-wrapped blob, not a key.
# This sits between Part 6 (enrolment) and Part 7 (login) and is the claim the
# rest of the lab rests on — the written guide asserts it but never shows it.
# Print every command before running it so the operator can reproduce the proof
# interactively rather than having to trust the script's summary.
set -euo pipefail
STAGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${STAGE_DIR}/common.sh"

DEVICE="${1:-node01}"
KEY="${LAB_PKI_DIR}/${DEVICE}.tpmkey.pem"
EXPORT_ATTEMPT="${VM_STAGE}/${DEVICE}-export-attempt.pem"
TSS2_HEADER="-----BEGIN TSS2 PRIVATE KEY-----"

log_step "Proof: the private key cannot leave the TPM (${DEVICE})"

[[ -f "${LAB_DIR}/env.sh" ]] || die "no ${LAB_DIR}/env.sh — run 'task provision' first"
[[ -f "${KEY}" ]] || die "no key at ${KEY} — run 'task enrol' first"
trap 'rm -f "${EXPORT_ATTEMPT}"' EXIT

# --- 1. ask OpenSSL to serialise the provider-managed key -------------------
log_step "1. Ask OpenSSL to write the TPM key"
log_detail "$ openssl pkey -provider default -provider tpm2 \\"
log_detail "    -in ${KEY} -out ${EXPORT_ATTEMPT}"
as_lab_user openssl pkey -provider default -provider tpm2 \
  -in "${KEY}" -out "${EXPORT_ATTEMPT}"

log_info ""
log_detail "$ head -1 ${EXPORT_ATTEMPT}"
export_header="$(head -1 "${EXPORT_ATTEMPT}")"
printf '%s\n' "${export_header}"
if [[ "${export_header}" == "${TSS2_HEADER}" ]]; then
  log_info ""
  log_info "Despite its name, 'TSS2 PRIVATE KEY' is a TPM object container."
  log_info "It contains a public area and an encrypted private area, not the EC"
  log_info "private scalar. It can perform private operations only through its TPM."
else
  die "unexpected export format — inspect ${EXPORT_ATTEMPT}"
fi

# --- 2. prove the output is unusable as an ordinary private key -------------
log_step "2. Try to read that output without the TPM provider"
log_detail "$ openssl pkey -in ${EXPORT_ATTEMPT} -noout -text"
rc=0
out="$(as_lab_user_allow_fail openssl pkey -in "${EXPORT_ATTEMPT}" -noout -text 2>&1)" || rc=$?
printf '%s\n' "${out}"
log_detail "(exit ${rc})"
if (( rc != 0 )); then
  log_ok "the default provider cannot decode it because no private key was exported"
else
  die "the output was readable without the TPM provider — it is not TPM-wrapped"
fi

# --- 3. what the bytes actually are -----------------------------------------
log_step "3. Inspect the wrapped object's ASN.1 structure"
log_detail "$ openssl asn1parse -in ${EXPORT_ATTEMPT}"
asn_rc=0
asn_out="$(as_lab_user_allow_fail openssl asn1parse -in "${EXPORT_ATTEMPT}" 2>&1)" || asn_rc=$?
printf '%s\n' "${asn_out}" | sed 's/^/  /'
if (( asn_rc == 0 )); then
  # grep -c exits 1 on no match; the count is what matters, not the status.
  octets="$(printf '%s\n' "${asn_out}" | grep -c 'OCTET STRING' || true)"
  log_ok "${octets} opaque OCTET STRINGs hold the public area and encrypted TPM-private area"
else
  die "could not parse the TPM wrapper (exit ${asn_rc})"
fi

# --- 4. the asymmetry: the public half does come out ------------------------
log_step "4. Export the public key"
log_detail "$ openssl pkey -provider default -provider tpm2 \\"
log_detail "    -in ${KEY} -pubout"
pub_rc=0
pub_out="$(as_lab_user_allow_fail openssl pkey -provider default -provider tpm2 \
  -in "${KEY}" -pubout 2>&1)" || pub_rc=$?
if (( pub_rc == 0 )); then
  printf '%s\n' "${pub_out}" | sed 's/^/  /'
  log_ok "the public key is exportable; the private key remains TPM-wrapped"
else
  printf '%s\n' "${pub_out}"
  die "could not extract the public key (exit ${pub_rc})"
fi

# --- close -------------------------------------------------------------------
log_info ''
log_info "This blob is encrypted to this TPM's storage root key, so it is useless on"
log_info "any other machine: copying it buys an attacker nothing without the silicon"
log_info "that unwraps it. The bonus stolen-key test proves that by pointing it at"
log_info "a second TPM and watching the login fail."
