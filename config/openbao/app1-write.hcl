# Policy app1-write (docs/DECISIONS.md D12): short-lived WRITE
# access to the app1 PostgreSQL primary (OpenBao role app1-pg-rw, 30 min, temp users in
# debug_rw). Granted only through the identity group app1-devs-rw, which follows the Keycloak
# group app1-devs-rw; only the approval portal adds people to it, after a second person in
# app1-write-approvers approved. Written by scripts/setup-portal.ps1.
path "database/creds/app1-pg-rw" { capabilities = ["read"] }
