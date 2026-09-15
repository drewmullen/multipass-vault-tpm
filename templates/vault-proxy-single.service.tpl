# Workflow 2 reference. Authoritative generated copy: scripts/81_single_proxy.sh.
[Unit]
Description=Single-workload Vault Agent HTTP proxy (TPM auto-auth)
After=network-online.target vault-dev.service swtpm-unix-bridge.service
Wants=vault-dev.service swtpm-unix-bridge.service

[Service]
Type=simple
ExecStart=/usr/local/bin/vault agent -config=/etc/vault-proxy/single.hcl
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
