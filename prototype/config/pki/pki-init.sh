#!/bin/sh
# One-shot lab PKI for phase 1. Runs as root in a throwaway container and writes into named volumes:
#   /pki-ca-key  CA private key + CA cert (mounted ONLY into this init service)
#   /pki-ca      ca.crt only (mounted read-only into clients)
#   /pki-pg      server.crt + server.key for pg-primary   (uid 999, key 0600)
#   /pki-maria   server.crt + server.key for maria-primary (uid 999, key 0600)
# Optional certificates, each handled only when its volume is mounted, so earlier phases are
# unchanged:
#   /pki-bao            openbao (uid 100, key 0600). Phase 2 and later.
#   /pki-pg-replica     pg-replica (uid 999, key 0600). Phase 3 and later.
#   /pki-maria-replica  maria-replica (uid 999, key 0600). Phase 3 and later.
# Idempotent: if every file exists it only re-applies ownership and modes. A missing optional
# certificate (a later phase started on an existing CA) is issued from the existing CA.
set -eu

DAYS_CA=3650
DAYS_SERVER=397
SERVER_UID=999
SERVER_GID=999
# uid/gid of user "openbao" in the official openbao/openbao image.
BAO_UID=100
BAO_GID=1000
# Names in the OpenBao certificate: service name, plus localhost/127.0.0.1 for the published
# port and for the bao CLI inside the container.
BAO_SAN="DNS:openbao,DNS:localhost,IP:127.0.0.1"

# Optional certificates: "name|dir|subjectAltName|uid|gid" (one per line).
OPTIONAL="openbao|/pki-bao|$BAO_SAN|$BAO_UID|$BAO_GID
pg-replica|/pki-pg-replica|DNS:pg-replica|$SERVER_UID|$SERVER_GID
maria-replica|/pki-maria-replica|DNS:maria-replica|$SERVER_UID|$SERVER_GID"

# Calls "$1 name dir san uid gid" for every optional certificate whose volume is mounted.
for_each_optional() {
    echo "$OPTIONAL" | while IFS='|' read -r o_name o_dir o_san o_uid o_gid; do
        if [ -d "$o_dir" ]; then "$1" "$o_name" "$o_dir" "$o_san" "$o_uid" "$o_gid"; fi
    done
}

fix_one() {
    chown "$4:$5" "$2" "$2/server.crt" "$2/server.key"
    chmod 0700 "$2"
    chmod 0644 "$2/server.crt"
    chmod 0600 "$2/server.key"
}

fix_perms() {
    chmod 0700 /pki-ca-key
    chmod 0600 /pki-ca-key/ca.key
    chmod 0755 /pki-ca
    chmod 0644 /pki-ca/ca.crt
    for d in /pki-pg /pki-maria; do
        fix_one x "$d" x "$SERVER_UID" "$SERVER_GID"
    done
    for_each_optional fix_one
}

work="$(mktemp -d)"

issue() {
    name="$1"
    outdir="$2"
    san="${3:-DNS:$1}"
    cat > "$work/$name.ext" <<EOF
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = $san
authorityKeyIdentifier = keyid
subjectKeyIdentifier = hash
EOF
    (umask 077; openssl req -quiet -new -newkey rsa:2048 -nodes -sha256 -subj "/CN=$name" \
        -keyout "$outdir/server.key" -out "$work/$name.csr")
    openssl x509 -req -sha256 -days "$DAYS_SERVER" -in "$work/$name.csr" \
        -CA /pki-ca-key/ca.crt -CAkey /pki-ca-key/ca.key -set_serial "0x$(openssl rand -hex 16)" \
        -extfile "$work/$name.ext" -out "$outdir/server.crt"
    openssl verify -CAfile /pki-ca-key/ca.crt "$outdir/server.crt"
}

issue_optional_if_missing() {
    if ! { [ -s "$2/server.crt" ] && [ -s "$2/server.key" ]; }; then
        echo "pki-init: issuing the missing $1 certificate from the existing CA"
        issue "$1" "$2" "$3"
    fi
}

issue_optional() {
    issue "$1" "$2" "$3"
}

if [ -s /pki-ca-key/ca.key ] && [ -s /pki-ca/ca.crt ] \
   && [ -s /pki-pg/server.crt ] && [ -s /pki-pg/server.key ] \
   && [ -s /pki-maria/server.crt ] && [ -s /pki-maria/server.key ]; then
    echo "pki-init: CA and primary certificates already present"
    for_each_optional issue_optional_if_missing
    rm -rf "$work"
    fix_perms
    echo "pki-init: permissions re-applied"
    exit 0
fi

echo "pki-init: generating lab CA and server certificates"
umask 077

cat > "$work/ca.cnf" <<'EOF'
[req]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no
[dn]
CN = security-prototype phase1 lab CA
[v3_ca]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOF

openssl req -quiet -x509 -new -newkey rsa:3072 -nodes -sha256 -days "$DAYS_CA" \
    -config "$work/ca.cnf" -keyout /pki-ca-key/ca.key -out /pki-ca-key/ca.crt
cp /pki-ca-key/ca.crt /pki-ca/ca.crt

issue pg-primary /pki-pg
issue maria-primary /pki-maria
for_each_optional issue_optional

rm -rf "$work"
fix_perms
echo "pki-init: done"
