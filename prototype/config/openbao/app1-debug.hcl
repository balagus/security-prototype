# Policy app1-debug (design section 5.5): read-only, masked, time-limited database access.
# Granted through the identity group app1-devs, which follows the Keycloak group app1-devs.
path "database/creds/app1-pg-ro"    { capabilities = ["read"] }
path "database/creds/app1-maria-ro" { capabilities = ["read"] }
