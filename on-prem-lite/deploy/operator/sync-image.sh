#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Sync a container image from an external registry into the operator's GCP
# Artifact Registry, so no-internet CVMs can pull it over Private Google Access.
# Uses skopeo (copies by digest → integrity-preserving; works for plaintext AND
# ocicrypt-encrypted images, which are copied verbatim).
#
#   ./sync-image.sh <src-ref> <dest-ref>
#
#   src-ref    e.g. cr.kvin.wang/lite-launcher@sha256:…  (vendor bundle dst_ref)
#   dest-ref   the FULL destination ref in the operator's AR, e.g.
#              us-central1-docker.pkg.dev/acme/dstack-private/lite-launcher:latest
#
# auth: short-lived OAuth token from the active gcloud identity (for the dest AR).
# optional: SRC_AUTHFILE (docker config json for the source registry).
set -euo pipefail

c_step() { printf '\n\033[1;36m▶ %s\033[0m\n' "$*"; }
c_ok()   { printf '  \033[0;32m✓ %s\033[0m\n' "$*"; }
c_die()  { printf '  \033[0;31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

SRC="${1:?usage: sync-image.sh <src-ref> <dest-ref>}"
DEST="${2:?usage: sync-image.sh <src-ref> <dest-ref>}"

TOKEN="$(gcloud auth print-access-token 2>/dev/null)" || c_die "gcloud auth print-access-token failed"
DEST_CREDS="oauth2accesstoken:${TOKEN}"

SRC_AUTH_ARGS=()
[[ -n "${SRC_AUTHFILE:-}" ]] && SRC_AUTH_ARGS=(--src-authfile "$SRC_AUTHFILE")

c_step "sync  ${SRC}  →  ${DEST}"
skopeo copy --all "${SRC_AUTH_ARGS[@]}" --dest-creds "$DEST_CREDS" \
    "docker://${SRC}" "docker://${DEST}"

DIGEST="$(skopeo inspect --creds "$DEST_CREDS" --format '{{.Digest}}' "docker://${DEST}" 2>/dev/null)"
c_ok "synced. pull as:  ${DEST%@*}@${DIGEST}"
echo "${DEST%@*}@${DIGEST}"
