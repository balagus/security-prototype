# Policy lease-reconciler (docs/DECISIONS.md D8): the OpenBao lease reconciler
# (config/reconciler/lease-reconciler.sh). It can find database leases, read their TTL and
# revoke them, nothing else: it cannot issue credentials (database/creds/*), read secrets or
# configuration, renew leases, or change anything. Each rule below was measured by removing it
# (tests\revocation-checks.ps1). Granted only to the AppRole role lease-reconciler, whose batch
# tokens are bound to the reconciler's address (10.81.10.20) and get no default policy.

# LIST the roles under database/creds/ and the lease ids of each role. LIST on
# sys/leases/lookup/<prefix> requires sudo.
path "sys/leases/lookup/database/creds/*" {
  capabilities = ["list", "sudo"]
}

# Look up one lease (TTL, expire time, and issue_time, which the PostgreSQL deny descriptors
# carry: the response fields are not restricted by policy, measured). The lease id is a body
# parameter; only database credential leases are allowed.
path "sys/leases/lookup" {
  capabilities = ["update"]
  allowed_parameters = {
    "lease_id" = ["database/creds/*"]
  }
}

# Revoke one database credential lease, synchronously (the result is known at once).
path "sys/leases/revoke" {
  capabilities = ["update"]
  allowed_parameters = {
    "lease_id" = ["database/creds/*"]
    "sync"     = ["true"]
  }
}

# List irrevocable leases (GET sys/leases?type=irrevocable requires sudo).
path "sys/leases" {
  capabilities = ["read", "sudo"]
}
