# OpenBao server configuration for phase 2. NOT dev mode: integrated Raft storage on a named
# volume, TLS listener with a certificate from the lab CA, audit device declared here.

ui = true

# No disable_mlock: OpenBao 2.7 no longer uses mlock and warns that the field is unknown.
# So no CAP_IPC_LOCK is needed and no-new-privileges needs no adjustment.

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
    mode      = "0600"
  }
}
