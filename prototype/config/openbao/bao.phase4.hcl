# OpenBao server configuration for phase 4 (compose.phase4.yaml). Identical to bao.hcl (phases
# 2 and 3) except for the audit file mode: 0640 instead of 0600, so the log shipper can read it.
# The bao-audit volume directory is owned by openbao (uid 100), group 4000 (log readers only,
# setgid, see config/logs/log-init.sh), so the file's group is 4000, not openbao's own group.
# The shipper mounts the volume read-only; nothing else mounts it.

ui = true

api_addr     = "https://openbao:8200"
cluster_addr = "https://openbao:8201"

storage "raft" {
  path    = "/openbao/file"
  node_id = "openbao-1"
}

listener "tcp" {
  address         = "0.0.0.0:8200"
  cluster_address = "0.0.0.0:8201"
  tls_cert_file   = "/pki-bao/server.crt"
  tls_key_file    = "/pki-bao/server.key"
  tls_min_version = "tls12"
}

# Declarative audit device. Since OpenBao 2.3.2 creating audit devices over the API is
# refused unless unsafe_allow_api_audit_creation = true, which this file does not set.
audit "file" "main" {
  description = "Authoritative person -> lease -> database username record"
  options {
    file_path = "/openbao/logs/audit.log"
    mode      = "0640"
  }
}
