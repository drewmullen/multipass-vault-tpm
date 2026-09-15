# Workflow 2 reference: one workload uses a normal localhost HTTP URL.
# The authoritative generated copy is in scripts/81_single_proxy.sh.

vault {
  address = "https://127.0.0.1:8200"
  ca_cert = "${LAB_TLS_DIR}/vault-ca.pem"
}

tpm_cert "workload_identity" {
  mount_path = "auth/tpm"
  role_name  = "payments-app"

  tpm {
    device_path = "${SWTPM_UNIX_SOCK}"
  }

  csr {
    CN = "${DEVICE_CN}"
  }

  destination {
    path  = "/var/lib/vault-agent/single/tpm"
    umask = "077"
  }
}

auto_auth {
  method "tpm" {
    mount_path = "auth/tpm"
    config = {
      tpm_cert  = "workload_identity"
      role_name = "payments-app"
    }
  }
}

api_proxy {
  use_auto_auth_token = "force"
}

listener "tcp" {
  address     = "127.0.0.1:8100"
  tls_disable = true
}
