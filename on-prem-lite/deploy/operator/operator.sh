#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# OPERATOR CLI · deploy + license one on-prem-lite workload CVM on GCP.
#
# the operator pastes the vendor's printed install command, which sets
# AUTHORITY_API_KEY + AUTHORITY_URL and runs:
#
#   AUTHORITY_API_KEY=… AUTHORITY_URL=… ./operator.sh install <app-id>
#
# subcommands:
#   install <app-id>   fetch bundle → write deploy dir → sync images → deploy CVM → license
#   sync    <app-id>   re-sync the bundle's two images into the operator's AR (install step 3)
#   update  <app-id>   re-run the courier license flow only (renew / rolling update)
#   status             IAP-tunnel to the launcher /status
#   healthz            IAP-tunnel to the launcher /healthz
#
# config.env (next to this script, gitignored, generated on first run): GCP_PROJECT,
#   GCP_ZONE, AR_LOCATION/AR_PROJECT/AR_REPO, WORKLOAD_IP, OS_VERSION.
set -euo pipefail

# ─── paths ────────────────────────────────────────────────────────────────────
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"            # …/on-prem-lite/deploy/operator
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"                        # repo root
DC="${DSTACK_CLOUD:-$REPO_ROOT/scripts/bin/dstack-cloud}"                        # repo-relative dstack-cloud
DEPLOY_DIR="$HERE/deploy-work"                                  # generated deploy dir
CONFIG="$HERE/config.env"

# ─── output helpers ───────────────────────────────────────────────────────────
c_step() { printf '\n\033[1;36m▶ %s\033[0m\n' "$*"; }
c_ok()   { printf '  \033[0;32m✓ %s\033[0m\n' "$*"; }
c_warn() { printf '  \033[1;33m%s\033[0m\n' "$*"; }
c_die()  { printf '  \033[0;31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

# ─── config.env ───────────────────────────────────────────────────────────────
write_config_template() {
    cat > "$CONFIG" <<'EOF'
# SPDX-License-Identifier: Apache-2.0
# operator deploy config — edit then re-run `./operator.sh install <app-id>`.

# GCP project + zone the workload CVM runs in.
GCP_PROJECT=
GCP_ZONE=us-central1-a

# operator's Artifact Registry the CVM pulls images from (over Private Google
# Access). AR_LOCATION defaults to the zone's region; AR_PROJECT to GCP_PROJECT.
AR_LOCATION=
AR_PROJECT=
AR_REPO=dstack-private

# static internal IP to bind the workload CVM to (reserved automatically).
WORKLOAD_IP=

# OS image published name, dotted (e.g. dstack-cloud-nvidia-0.6.1). dots become
# dashes for the local image dir / app.json os_image.
OS_VERSION=
EOF
    c_ok "wrote config template: $CONFIG"
}

load_config() {
    [[ -f "$CONFIG" ]] || return 1
    # shellcheck disable=SC1090
    source "$CONFIG"
    : "${GCP_PROJECT:?set GCP_PROJECT in config.env}"
    : "${GCP_ZONE:?set GCP_ZONE in config.env}"
    : "${WORKLOAD_IP:?set WORKLOAD_IP in config.env}"
    : "${OS_VERSION:?set OS_VERSION in config.env}"
    REGION="${GCP_ZONE%-*}"
    AR="${AR_LOCATION:-$REGION}-docker.pkg.dev/${AR_PROJECT:-$GCP_PROJECT}/${AR_REPO:-dstack-private}"
    BUCKET="gs://${GCP_PROJECT}-dstack"
    OS_IMAGE="${OS_VERSION//./-}"
    WL_INSTANCE=dstack-lite-workload
}

# ─── dstack-cloud global config (project/zone + image search path; no kms) ─────
bootstrap_dstack() {
    local f="$HOME/.config/dstack-cloud/config.json"
    mkdir -p "$(dirname "$f")"; [[ -f "$f" ]] || echo '{}' >"$f"
    python3 - "$f" "$GCP_PROJECT" "$GCP_ZONE" <<'PY'
import json,sys
f,proj,zone=sys.argv[1:4]
try: d=json.load(open(f))
except Exception: d={}
d.setdefault("gcp",{})
d["gcp"]["project"],d["gcp"]["zone"]=proj,zone
d.setdefault("image_search_paths",["~/.dstack/images"])
json.dump(d,open(f,"w"),indent=2)
PY
    c_ok "dstack-cloud config: project=$GCP_PROJECT image_search_paths=~/.dstack/images (no kms — lite)"
}

# ─── authority bundle ─────────────────────────────────────────────────────────
fetch_bundle() { # app-id  → writes $BUNDLE_FILE
    : "${AUTHORITY_URL:?set AUTHORITY_URL (env)}" "${AUTHORITY_API_KEY:?set AUTHORITY_API_KEY (env)}"
    BUNDLE_FILE="$(mktemp)"
    c_step "fetch bundle for app $1"
    local code
    code="$(curl -sS -o "$BUNDLE_FILE" -w '%{http_code}' \
        -H "Authorization: Bearer $AUTHORITY_API_KEY" \
        "${AUTHORITY_URL%/}/api/v1/app/$1/bundle" || true)"
    [[ "$code" == 200 ]] || c_die "bundle fetch failed (http $code): $(head -c 300 "$BUNDLE_FILE" 2>/dev/null)"
    python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$BUNDLE_FILE" \
        || c_die "bundle response is not valid json"
    c_ok "got bundle"
}

bjq() { python3 - "$BUNDLE_FILE" "$1" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
cur=d
for k in sys.argv[2].split("."):
    if isinstance(cur,dict) and k in cur: cur=cur[k]
    else: cur=""; break
# write VERBATIM (no trailing newline): the docker_compose / prelaunch strings are
# embedded byte-for-byte into the measured app-compose.json, so an extra newline
# would change compose_hash. (command substitution strips trailing newlines anyway.)
sys.stdout.write(cur if isinstance(cur,str) else json.dumps(cur))
PY
}

# ─── deploy dir from the bundle ───────────────────────────────────────────────
write_deploy_dir() { # app-id
    c_step "write deploy dir $DEPLOY_DIR"
    rm -rf "$DEPLOY_DIR"; mkdir -p "$DEPLOY_DIR"
    bjq docker_compose > "$DEPLOY_DIR/docker-compose.yaml"
    bjq prelaunch      > "$DEPLOY_DIR/prelaunch.sh"; chmod +x "$DEPLOY_DIR/prelaunch.sh"
    bjq app_json       > "$DEPLOY_DIR/app.json"

    # set app_id + gcp fields + os_image in app.json (these are not measured).
    python3 - "$DEPLOY_DIR/app.json" "$1" "$WL_INSTANCE" "$WORKLOAD_IP" \
        "$GCP_PROJECT" "$GCP_ZONE" "$BUCKET" "$OS_IMAGE" <<'PY'
import json,sys
f,app_id,name,ip,proj,zone,bucket,osimg=sys.argv[1:9]
d=json.load(open(f)); g=d.setdefault("gcp_config",{})
d["app_id"]=app_id
g["project"],g["zone"],g["bucket"]=proj,zone,bucket
g["private_ip"],g["instance_name"]=ip,name
d["os_image"]=osimg
json.dump(d,open(f,"w"),indent=2)
PY
    printf '{ "DSTACK_REGISTRY": "%s" }\n' "$AR" > "$DEPLOY_DIR/.user-config"
    c_ok "deploy dir ready (app_id=$1 registry=$AR)"
}

# ─── image sync (bundle dst_ref → operator AR, digest-preserving) ─────────────
sync_one() { # image_name  src_ref
    local name="$1" src="$2"
    [[ -n "$src" ]] || c_die "bundle missing dst_ref for $name"
    c_step "sync $name → AR"
    "$HERE/sync-image.sh" "$src" "$AR/$name:latest" | tail -1
}

do_sync_images() {
    sync_one lite-launcher "$(bjq lite_launcher.dst_ref)"
    local wl_name; wl_name="$(bjq workload.image_name)"
    sync_one "$wl_name" "$(bjq workload.dst_ref)"
    c_step "pull OS image $OS_VERSION"
    [[ -f "$HOME/.dstack/images/$OS_IMAGE/disk.raw" ]] && c_ok "already pulled" || "$DC" pull "$OS_VERSION"
}

# ─── deploy the CVM ───────────────────────────────────────────────────────────
reserve_ip() {
    gcloud compute addresses create dstack-lite-workload-ip --project="$GCP_PROJECT" \
        --region="$REGION" --subnet=default --addresses="$WORKLOAD_IP" 2>/dev/null \
        && c_ok "reserved dstack-lite-workload-ip=$WORKLOAD_IP" || c_ok "ip already reserved"
}

do_deploy_cvm() {
    c_step "deploy workload CVM"
    reserve_ip
    "$DC" -C "$DEPLOY_DIR" prepare

    # assert the locally-built launcher compose_hash matches the bundle's: a
    # mismatch means our build diverged from the vendor's trusted launcher build.
    local local_ch bundle_ch
    local_ch="$(sha256sum "$DEPLOY_DIR/shared/app-compose.json" | cut -d' ' -f1)"
    bundle_ch="$(bjq compose_hash)"
    [[ "$local_ch" == "$bundle_ch" ]] \
        || c_die "compose_hash mismatch: local=$local_ch bundle=$bundle_ch (launcher build diverged)"
    c_ok "compose_hash matches bundle: $local_ch"

    "$DC" -C "$DEPLOY_DIR" deploy
    "$DC" -C "$DEPLOY_DIR" fw allow 9000 || true   # courier port over IAP
    c_ok "deployed $WL_INSTANCE"
}

# ─── courier (IAP tunnel + license-ctl), hardened free-port guard ─────────────
tunnel() { # remote_port local_port  → echoes PID
    gcloud compute start-iap-tunnel "$WL_INSTANCE" "$1" --local-host-port="localhost:$2" \
        --project="$GCP_PROJECT" --zone="$GCP_ZONE" >/dev/null 2>&1 &
    echo $!
}

# open a tunnel on a per-process local port, freeing any stale listener first.
# echoes "PID LP". caller must `trap 'kill PID' RETURN` and use $LP.
open_tunnel() { # remote_port
    local LP=$((19000 + ($$ % 900)))
    local stale; stale="$(ss -ltnpH "sport = :$LP" 2>/dev/null | grep -oP 'pid=\K[0-9]+' | sort -u || true)"
    [ -n "$stale" ] && { kill $stale 2>/dev/null || true; sleep 1; }
    local pid; pid="$(tunnel "$1" "$LP")"
    echo "$pid $LP"
}

wait_healthz() { # pid local_port remote_port
    local pid="$1" LP="$2" rp="$3" hz=""
    c_step "waiting for launcher on the tunnel (CVM may still be booting)"
    for _ in $(seq 1 90); do
        kill -0 "$pid" 2>/dev/null || pid="$(tunnel "$rp" "$LP")"   # respawn if the tunnel died
        hz="$(curl -s --max-time 3 "http://localhost:$LP/healthz" 2>/dev/null || true)"
        [ -n "$hz" ] && break
        sleep 4
    done
    [ -n "$hz" ] || c_die "launcher not reachable on :$LP after ~6min (CVM booted? is 'fw allow 9000' applied?)"
    c_ok "launcher healthz: $hz"
}

do_license() { # app-id
    : "${AUTHORITY_URL:?set AUTHORITY_URL (env)}" "${AUTHORITY_API_KEY:?set AUTHORITY_API_KEY (env)}"
    local app_id="$1"
    local wl_name wl_digest workload_image
    wl_name="$(bjq workload.image_name)"
    wl_digest="$(bjq workload.digest)"
    [[ -n "$wl_name" && -n "$wl_digest" ]] || c_die "bundle missing workload image_name/digest"
    workload_image="$AR/$wl_name"   # operator's AR ref; digest is the security anchor

    local t pid LP
    t="$(open_tunnel 9000)"; pid="${t%% *}"; LP="${t##* }"
    # self-clearing RETURN trap: kill the tunnel AND remove the trap when this
    # function returns, so it never leaks to the caller's return (set -u would
    # then trip on the now-unbound $pid). guard $pid for the same reason.
    trap 'kill "${pid:-}" 2>/dev/null || true; trap - RETURN' RETURN
    c_step "opened IAP tunnel localhost:$LP → $WL_INSTANCE:9000"
    wait_healthz "$pid" "$LP" 9000

    # USER_ID: the authority resolves the tenant from AUTHORITY_API_KEY (the api
    # key IS the tenant credential), so we pass an empty user_id and let the
    # authority bind the challenge + license to the keyed tenant.
    c_step "courier attest (app_id=$app_id workload_image=$workload_image)"
    LAUNCHER_URL="http://localhost:$LP" \
    AUTHORITY_URL="$AUTHORITY_URL" \
    USER_ID="${USER_ID:-}" \
    APP_ID="$app_id" \
    WORKLOAD_IMAGE="$workload_image" \
    WORKLOAD_DIGEST="$wl_digest" \
    AUTHORITY_API_KEY="$AUTHORITY_API_KEY" \
        python3 "$REPO_ROOT/on-prem-lite/cli/license-ctl.py" attest

    c_step "waiting for the workload to come up (decrypt + run takes a moment)"
    local st=""
    for _ in $(seq 1 30); do
        st="$(curl -s --max-time 4 "http://localhost:$LP/status" 2>/dev/null || true)"
        echo "$st" | grep -q '"workload_running": *true' && break
        sleep 6
    done
    if [ -n "$st" ]; then echo "$st" | python3 -m json.tool; else c_warn "/status not ready — check launcher logs"; fi
}

# ─── simple IAP-tunnel GET (status / healthz) ─────────────────────────────────
tunnel_get() { # path
    local t pid LP
    t="$(open_tunnel 9000)"; pid="${t%% *}"; LP="${t##* }"
    # self-clearing RETURN trap: kill the tunnel AND remove the trap when this
    # function returns, so it never leaks to the caller's return (set -u would
    # then trip on the now-unbound $pid). guard $pid for the same reason.
    trap 'kill "${pid:-}" 2>/dev/null || true; trap - RETURN' RETURN
    c_step "opened IAP tunnel localhost:$LP → $WL_INSTANCE:9000"
    # brief wait for the tunnel to be ready.
    for _ in $(seq 1 15); do
        curl -s --max-time 3 "http://localhost:$LP$1" 2>/dev/null && { echo; return 0; }
        sleep 2
    done
    c_die "no response from launcher$1 (CVM up? fw allow 9000 applied?)"
}

# ─── subcommands ──────────────────────────────────────────────────────────────
cmd_install() { # app-id
    local app_id="${1:?usage: operator.sh install <app-id>}"
    fetch_bundle "$app_id"
    if ! load_config 2>/dev/null; then
        [[ -f "$CONFIG" ]] || write_config_template
        c_warn "edit $CONFIG (GCP_PROJECT/ZONE, AR_*, WORKLOAD_IP, OS_VERSION) then re-run:"
        c_warn "  AUTHORITY_API_KEY=… AUTHORITY_URL=… $0 install $app_id"
        exit 0
    fi
    bootstrap_dstack
    write_deploy_dir "$app_id"
    do_sync_images
    do_deploy_cvm
    do_license "$app_id"
    c_step "usage"
    bjq usage_text
}

cmd_sync() { # app-id
    local app_id="${1:?usage: operator.sh sync <app-id>}"
    fetch_bundle "$app_id"
    load_config || c_die "config.env missing — run install first"
    do_sync_images
}

cmd_update() { # app-id
    local app_id="${1:?usage: operator.sh update <app-id>}"
    fetch_bundle "$app_id"
    load_config || c_die "config.env missing — run install first"
    do_license "$app_id"
}

cmd_tunnel() { # path
    load_config || c_die "config.env missing — run install first"
    tunnel_get "$1"
}

case "${1:-}" in
    install) cmd_install "${2:-}" ;;
    sync)    cmd_sync "${2:-}" ;;
    update)  cmd_update "${2:-}" ;;
    status)  cmd_tunnel /status ;;
    healthz) cmd_tunnel /healthz ;;
    *) echo "usage: $0 {install|sync|update|status|healthz} [<app-id>]"; exit 1 ;;
esac
