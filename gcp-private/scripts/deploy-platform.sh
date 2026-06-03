#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Deploy the VENDOR-side stack (vendor platform + dstack-verifier) via
# docker-compose. Runs on the vendor's infrastructure (needs internet for PCCS
# and OS-image collateral). Prints the platform Ed25519 pubkey to configure into
# the KMS key-broker (deploy-kms.sh consumes it).

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

cd "$ROOT"

c_step "building + starting platform stack (verifier + platform)"
REQUIRE_ATTESTATION="${REQUIRE_ATTESTATION:-true}" \
EXPECTED_OS_IMAGE_HASH="${EXPECTED_OS_IMAGE_HASH:-}" \
PLATFORM_ADMIN_TOKEN="${PLATFORM_ADMIN_TOKEN:-}" \
PLATFORM_NONCE_SECRET="${PLATFORM_NONCE_SECRET:-}" \
PLATFORM_SIGNING_KEY="${PLATFORM_SIGNING_KEY:-}" \
PCCS_URL="${PCCS_URL:-https://pccs.phala.network}" \
VERIFIER_IMAGE="${VERIFIER_IMAGE:-cr.kvin.wang/dstack-verifier:latest}" \
    docker compose -f docker-compose.platform.yml up -d --build

c_step "waiting for platform + verifier health"
for _ in $(seq 1 40); do
    curl -sf "${PLATFORM_URL}/api/v1/platform-pubkey" >/dev/null 2>&1 && break
    sleep 0.5
done
curl -sf "${PLATFORM_URL}/api/v1/platform-pubkey" >/dev/null 2>&1 \
    || c_die "platform did not become healthy at ${PLATFORM_URL}"
c_ok "platform up at ${PLATFORM_URL}"

PUBKEY="$(curl -s "${PLATFORM_URL}/api/v1/platform-pubkey" | python3 -c 'import sys,json;print(json.load(sys.stdin)["pubkey"])')"
c_ok "platform pubkey (stable across restarts): ${PUBKEY}"
echo "$PUBKEY" > "$HERE/.platform-pubkey"

cat <<EOF

Next:
  - copy this pubkey into the KMS key-broker:  PLATFORM_PUBKEY=${PUBKEY}
  - run:  ./deploy-kms.sh        (uses .platform-pubkey automatically)
  - then: ./provision-kms.sh
EOF
