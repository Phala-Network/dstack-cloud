#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# VENDOR CLI — on-prem-lite authority.
#
# Implements the "Vendor CLI" subcommands from on-prem-lite/REDESIGN.md against the
# app-centric authority. Persists secrets/config in .vendor-config (next to this
# script, gitignored) and re-sources it each run. All admin calls use
#   Authorization: Bearer $AUTHORITY_ADMIN_TOKEN
#
#   ./authority.sh launch [--launcher-image <ref>] [--os-version <v>]
#   ./authority.sh add-cek <name>
#   ./authority.sh enc-img --cek <name> --image-name <n> <src> <dst>
#   ./authority.sh add-user <username>
#   ./authority.sh add-app <appname> --image-name <n> [--usage <text>]
#   ./authority.sh grant-app --user <u> --app <appname|app-id>
#   ./authority.sh install-cmd --app <appname|app-id> --user <u>

set -euo pipefail

# ── locate ourselves + the repo root (robust to symlinks/relative invocation) ──
HERE="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"  # deploy/vendor/
LITE_ROOT="$(cd "$HERE/../.." && pwd)"                                  # on-prem-lite/
REPO_ROOT="$(cd "$LITE_ROOT/.." && pwd)"                                # repo root
TEMPLATES="$LITE_ROOT/deploy/templates"
COMPOSE="$LITE_ROOT/docker-compose.authority.yml"
DC="$REPO_ROOT/scripts/bin/dstack-cloud"

CONFIG="$HERE/.vendor-config"
CEK_DIR="$HERE/.ceks"
USER_DIR="$HERE/.users"

# ── tiny coloured logging (lowercase messages) ─────────────────────────────────
c_step()  { printf '\n\033[1;36m▶ %s\033[0m\n' "$*"; }
c_ok()    { printf '  \033[0;32m✓ %s\033[0m\n' "$*"; }
c_warn()  { printf '  \033[1;33m%s\033[0m\n' "$*" >&2; }
c_die()   { printf '  \033[0;31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

# ── json field reader (stdin → value of top-level key, '' if absent) ──────────
jqr() { python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('$1','') if isinstance(d,dict) else '')"; }

# ── persist a KEY=value into .vendor-config (replace-or-append) ────────────────
persist() {
    local key="$1" val="$2"
    touch "$CONFIG"
    if grep -q "^${key}=" "$CONFIG" 2>/dev/null; then
        python3 - "$CONFIG" "$key" "$val" <<'PY'
import sys
path, key, val = sys.argv[1:4]
lines = open(path).read().splitlines()
out = [f"{key}={val}" if l.split('=', 1)[0] == key else l for l in lines]
open(path, 'w').write('\n'.join(out) + '\n')
PY
    else
        printf '%s=%s\n' "$key" "$val" >> "$CONFIG"
    fi
}

load_config() {
    if [[ -f "$CONFIG" ]]; then
        # shellcheck disable=SC1090
        source "$CONFIG"
    fi
}

# ── admin curl helper: admin_curl METHOD PATH [json-body] ─────────────────────
admin_curl() {
    local method="$1" path="$2" body="${3:-}"
    [[ -n "${AUTHORITY_ADMIN_TOKEN:-}" ]] || c_die "AUTHORITY_ADMIN_TOKEN not set (run 'launch' first)"
    if [[ -n "$body" ]]; then
        curl -sf -X "$method" \
            -H "Authorization: Bearer $AUTHORITY_ADMIN_TOKEN" \
            -H 'content-type: application/json' \
            -d "$body" "$AUTHORITY_URL$path"
    else
        curl -sf -X "$method" \
            -H "Authorization: Bearer $AUTHORITY_ADMIN_TOKEN" \
            "$AUTHORITY_URL$path"
    fi
}

require_url() { [[ -n "${AUTHORITY_URL:-}" ]] || c_die "AUTHORITY_URL not set (run 'launch' first)"; }

# ════════════════════════════════════════════════════════════════════════════
# launch
# ════════════════════════════════════════════════════════════════════════════
cmd_launch() {
    local launcher_image="" os_version=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --launcher-image) launcher_image="$2"; shift 2 ;;
            --os-version)     os_version="$2";     shift 2 ;;
            *) c_die "launch: unknown arg: $1" ;;
        esac
    done

    load_config

    # ── first-run secret generation + defaults (persist once, reuse thereafter) ─
    [[ -n "${AUTHORITY_URL:-}" ]]          || { AUTHORITY_URL="http://localhost:8084"; persist AUTHORITY_URL "$AUTHORITY_URL"; }
    [[ -n "${AUTHORITY_ADMIN_TOKEN:-}" ]]  || { AUTHORITY_ADMIN_TOKEN="$(openssl rand -hex 32)";  persist AUTHORITY_ADMIN_TOKEN "$AUTHORITY_ADMIN_TOKEN"; c_ok "generated admin token"; }
    [[ -n "${AUTHORITY_NONCE_SECRET:-}" ]] || { AUTHORITY_NONCE_SECRET="$(openssl rand -hex 32)"; persist AUTHORITY_NONCE_SECRET "$AUTHORITY_NONCE_SECRET"; c_ok "generated nonce secret"; }
    [[ -n "${AUTHORITY_SIGNING_KEY:-}" ]]  || { AUTHORITY_SIGNING_KEY="$(openssl rand -hex 32)";  persist AUTHORITY_SIGNING_KEY "$AUTHORITY_SIGNING_KEY"; c_ok "generated signing key"; }
    [[ -n "${PUBREG:-}" ]]                 || { PUBREG="cr.kvin.wang"; persist PUBREG "$PUBREG"; }

    # cli flags override persisted values
    [[ -n "$os_version" ]]     && OS_VERSION="$os_version"
    [[ -n "$launcher_image" ]] && LITE_LAUNCHER_REF="$launcher_image"
    [[ -n "${OS_VERSION:-}" ]]        || OS_VERSION=""   # may be empty; honoured by template default
    [[ -n "${LITE_LAUNCHER_REF:-}" ]] || LITE_LAUNCHER_REF="cr.kvin.wang/lite-launcher:latest"
    persist OS_VERSION "$OS_VERSION"
    persist LITE_LAUNCHER_REF "$LITE_LAUNCHER_REF"

    # ── 1. bring up the authority + verifier stack ─────────────────────────────
    c_step "starting authority + verifier (docker compose up -d --build)"
    [[ -f "$COMPOSE" ]] || c_die "compose file not found: $COMPOSE"
    docker compose -f "$COMPOSE" --env-file "$CONFIG" up -d --build

    c_step "waiting for authority health at $AUTHORITY_URL"
    local up=""
    for _ in $(seq 1 60); do
        if curl -sf "$AUTHORITY_URL/api/v1/authority-pubkey" >/dev/null 2>&1; then up=1; break; fi
        sleep 0.5
    done
    [[ -n "$up" ]] || c_die "authority did not become healthy at $AUTHORITY_URL"
    c_ok "authority up at $AUTHORITY_URL"

    # ── 2. fetch + persist the signing pubkey (pinned into the launcher build) ──
    AUTHORITY_PUBKEY="$(curl -sf "$AUTHORITY_URL/api/v1/authority-pubkey" | jqr pubkey)"
    [[ -n "$AUTHORITY_PUBKEY" ]] || c_die "could not read authority pubkey"
    persist AUTHORITY_PUBKEY "$AUTHORITY_PUBKEY"
    c_ok "AUTHORITY_PUBKEY=$AUTHORITY_PUBKEY"

    # ── 3. set up the single trusted launcher build ────────────────────────────
    c_step "resolve lite-launcher digest ($LITE_LAUNCHER_REF)"
    local digest
    digest="$(skopeo inspect "docker://$LITE_LAUNCHER_REF" --format '{{.Digest}}')"
    [[ "$digest" == sha256:* ]] || c_die "skopeo did not return a digest for $LITE_LAUNCHER_REF: $digest"
    c_ok "lite-launcher digest=$digest"

    [[ -d "$TEMPLATES" ]] || c_die "templates dir not found: $TEMPLATES"
    local tmp
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' RETURN
    cp -a "$TEMPLATES"/. "$tmp/"
    [[ -f "$tmp/docker-compose.yaml" ]] || c_die "templates missing docker-compose.yaml"
    [[ -f "$tmp/app.json" ]]            || c_die "templates missing app.json"
    [[ -f "$tmp/prelaunch.sh" ]]        || c_die "templates missing prelaunch.sh"

    c_step "render launcher compose (pin digest + AUTHORITY_PUBKEY)"
    local digest_bare="${digest#sha256:}"
    sed -i \
        -e "s|<PINNED_LITE_LAUNCHER_DIGEST>|$digest_bare|g" \
        -e "s|sha256:<PINNED_LITE_LAUNCHER_DIGEST>|$digest|g" \
        -e "s|lite-launcher:latest|lite-launcher@$digest|g" \
        -e "s|<PINNED_LITERAL_BASE64_AUTHORITY_PUBKEY>|$AUTHORITY_PUBKEY|g" \
        "$tmp/docker-compose.yaml"

    # app.json: os_image = OS_VERSION with dots → dashes; key_provider = tpm
    local os_image="${OS_VERSION//./-}"
    python3 - "$tmp/app.json" "$os_image" <<'PY'
import json, sys
f, os_image = sys.argv[1:3]
d = json.load(open(f))
if os_image:
    d["os_image"] = os_image
d["key_provider"] = "tpm"
json.dump(d, open(f, "w"), indent=2)
PY
    c_ok "app.json os_image=${os_image:-<template default>} key_provider=tpm"

    # ── 4. compute the launcher compose_hash via dstack-cloud prepare ──────────
    c_step "compute launcher compose_hash (dstack-cloud prepare)"
    [[ -x "$DC" ]] || c_die "dstack-cloud not found/executable at $DC"
    "$DC" -C "$tmp" prepare >/dev/null
    local app_compose="$tmp/shared/app-compose.json"
    [[ -f "$app_compose" ]] || c_die "prepare did not produce $app_compose"

    # ── 5. register the single launcher build with the authority ───────────────
    c_step "register launcher build (POST /api/v1/admin/launcher)"
    local resp
    resp="$(python3 - "$tmp/docker-compose.yaml" "$tmp/app.json" "$tmp/prelaunch.sh" \
                       "$app_compose" "$LITE_LAUNCHER_REF" "$digest" <<'PY'
import json, sys
dc, aj, pl, ac, ll_dst, ll_digest = sys.argv[1:7]
print(json.dumps({
    "docker_compose":       open(dc).read(),
    "app_json":             open(aj).read(),
    "prelaunch":            open(pl).read(),
    "app_compose_json":     open(ac).read(),
    "lite_launcher_dst":    ll_dst,
    "lite_launcher_digest": ll_digest,
}))
PY
)"
    # send the (potentially large) JSON body directly with --data-binary.
    local out
    out="$(curl -sf -X POST \
        -H "Authorization: Bearer $AUTHORITY_ADMIN_TOKEN" \
        -H 'content-type: application/json' \
        --data-binary "$resp" \
        "$AUTHORITY_URL/api/v1/admin/launcher")" || c_die "failed to register launcher build"
    local compose_hash
    compose_hash="$(printf '%s' "$out" | jqr compose_hash)"
    [[ -n "$compose_hash" ]] || c_die "authority did not return compose_hash: $out"

    c_step "launcher build registered"
    c_ok "AUTHORITY_PUBKEY=$AUTHORITY_PUBKEY"
    c_ok "compose_hash=$compose_hash"
}

# ════════════════════════════════════════════════════════════════════════════
# add-cek <name>
# ════════════════════════════════════════════════════════════════════════════
cmd_add_cek() {
    local name="${1:-}"
    [[ -n "$name" ]] || c_die "usage: add-cek <name>"
    load_config; require_url

    c_step "create cek '$name' (POST /api/v1/admin/ceks)"
    local resp pub
    resp="$(admin_curl POST /api/v1/admin/ceks "{\"kid\":\"$name\"}")" || c_die "failed to create cek"
    pub="$(printf '%s' "$resp" | jqr pub_pem)"
    [[ -n "$pub" ]] || c_die "authority did not return pub_pem: $resp"

    mkdir -p "$CEK_DIR"
    printf '%s' "$pub" > "$CEK_DIR/$name.pub.pem"
    c_ok "saved cek pubkey → $CEK_DIR/$name.pub.pem"
}

# ════════════════════════════════════════════════════════════════════════════
# enc-img --cek <name> --image-name <n> <src> <dst>
# ════════════════════════════════════════════════════════════════════════════
cmd_enc_img() {
    local cek="" image_name="" src="" dst=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --cek)        cek="$2";        shift 2 ;;
            --image-name) image_name="$2"; shift 2 ;;
            -*) c_die "enc-img: unknown flag: $1" ;;
            *)
                if [[ -z "$src" ]]; then src="$1"
                elif [[ -z "$dst" ]]; then dst="$1"
                else c_die "enc-img: too many positional args"; fi
                shift ;;
        esac
    done
    [[ -n "$cek" && -n "$image_name" && -n "$src" && -n "$dst" ]] \
        || c_die "usage: enc-img --cek <name> --image-name <n> <src> <dst>"
    load_config; require_url

    # ensure the cek pubkey is present locally; fetch from the authority if not.
    local pub_file="$CEK_DIR/$cek.pub.pem"
    if [[ ! -s "$pub_file" ]]; then
        c_step "fetch cek '$cek' pubkey (GET /api/v1/admin/ceks)"
        mkdir -p "$CEK_DIR"
        admin_curl GET /api/v1/admin/ceks \
            | python3 -c "import sys,json
d=json.load(sys.stdin)
ceks=d.get('ceks', d if isinstance(d,list) else [])
pub=next((c['pub_pem'] for c in ceks if c.get('kid')=='$cek'),'')
open('$pub_file','w').write(pub) if pub else sys.exit(1)" \
            || c_die "cek '$cek' not found on the authority"
        c_ok "saved cek pubkey → $pub_file"
    fi

    c_step "JWE-encrypt $src → $dst"
    skopeo copy --encryption-key "jwe:$pub_file" "docker://$src" "docker://$dst"

    local digest
    digest="$(skopeo inspect "docker://$dst" --format '{{.Digest}}')"
    [[ "$digest" == sha256:* ]] || c_die "could not read digest of $dst: $digest"
    c_ok "encrypted image digest=$digest"

    c_step "register image '$image_name' (POST /api/v1/admin/images)"
    admin_curl POST /api/v1/admin/images \
        "{\"image_name\":\"$image_name\",\"dst_ref\":\"$dst\",\"digest\":\"$digest\",\"kid\":\"$cek\"}" \
        >/dev/null || c_die "failed to register image"
    c_ok "registered $image_name dst=$dst digest=$digest kid=$cek"
}

# ════════════════════════════════════════════════════════════════════════════
# add-user <username>
# ════════════════════════════════════════════════════════════════════════════
cmd_add_user() {
    local username="${1:-}"
    [[ -n "$username" ]] || c_die "usage: add-user <username>"
    load_config; require_url

    c_step "create user '$username' (POST /api/v1/admin/users)"
    local resp api_key
    resp="$(admin_curl POST /api/v1/admin/users "{\"user_id\":\"$username\"}")" || c_die "failed to create user"
    api_key="$(printf '%s' "$resp" | jqr api_key)"
    [[ -n "$api_key" ]] || c_die "authority did not return api_key: $resp"

    # api_keys are not re-fetchable (authority stores only the hash) — persist now.
    mkdir -p "$USER_DIR"
    ( umask 077; printf '%s' "$api_key" > "$USER_DIR/$username.key" )
    c_ok "user '$username' created; api_key saved → $USER_DIR/$username.key"
    printf '  api_key=%s\n' "$api_key"
}

# ════════════════════════════════════════════════════════════════════════════
# add-app <appname> --image-name <n> [--usage <text>]
# ════════════════════════════════════════════════════════════════════════════
cmd_add_app() {
    local appname="" image_name="" usage=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --image-name) image_name="$2"; shift 2 ;;
            --usage)      usage="$2";      shift 2 ;;
            -*) c_die "add-app: unknown flag: $1" ;;
            *)
                if [[ -z "$appname" ]]; then appname="$1"; else c_die "add-app: too many positional args"; fi
                shift ;;
        esac
    done
    [[ -n "$appname" && -n "$image_name" ]] || c_die "usage: add-app <appname> --image-name <n> [--usage <text>]"
    load_config; require_url

    c_step "create app '$appname' (POST /api/v1/admin/apps)"
    local body resp app_id
    body="$(python3 -c "import json,sys
d={'app_name':'$appname','image_name':'$image_name'}
u=sys.argv[1]
if u: d['usage_text']=u
print(json.dumps(d))" "$usage")"
    resp="$(admin_curl POST /api/v1/admin/apps "$body")" || c_die "failed to create app"
    app_id="$(printf '%s' "$resp" | jqr app_id)"
    [[ -n "$app_id" ]] || c_die "authority did not return app_id: $resp"
    c_ok "app '$appname' created"
    printf '  app_id=%s\n' "$app_id"
}

# ════════════════════════════════════════════════════════════════════════════
# grant-app --user <u> --app <appname|app-id>
# ════════════════════════════════════════════════════════════════════════════
cmd_grant_app() {
    local user="" app=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --user) user="$2"; shift 2 ;;
            --app)  app="$2";  shift 2 ;;
            *) c_die "grant-app: unknown arg: $1" ;;
        esac
    done
    [[ -n "$user" && -n "$app" ]] || c_die "usage: grant-app --user <u> --app <appname|app-id>"
    load_config; require_url

    c_step "grant '$user' → '$app' (POST /api/v1/admin/grants)"
    local resp app_id
    resp="$(admin_curl POST /api/v1/admin/grants "{\"user_id\":\"$user\",\"app\":\"$app\"}")" \
        || c_die "failed to grant app"
    app_id="$(printf '%s' "$resp" | jqr app_id)"
    c_ok "granted user=$user app_id=${app_id:-$app}"
}

# ════════════════════════════════════════════════════════════════════════════
# install-cmd --app <appname|app-id> --user <u>
# ════════════════════════════════════════════════════════════════════════════
cmd_install_cmd() {
    local app="" user=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --app)  app="$2";  shift 2 ;;
            --user) user="$2"; shift 2 ;;
            *) c_die "install-cmd: unknown arg: $1" ;;
        esac
    done
    [[ -n "$app" && -n "$user" ]] || c_die "usage: install-cmd --app <appname|app-id> --user <u>"
    load_config; require_url

    # resolve app_id: if it already looks like a 40-hex app_id, use it; else look it up.
    local app_id=""
    if [[ "$app" =~ ^[0-9a-fA-F]{40}$ ]]; then
        app_id="$app"
    else
        # resolve the app_name → app_id via the apps list (read-only).
        app_id="$(admin_curl GET /api/v1/admin/apps 2>/dev/null \
            | python3 -c "import sys,json
d=json.load(sys.stdin)
apps=d.get('apps', d if isinstance(d,list) else [])
print(next((a['app_id'] for a in apps if a.get('app_name')=='$app'),''))" 2>/dev/null || true)"
        [[ -n "$app_id" ]] || c_die "could not resolve app_id for '$app' (no GET /admin/apps match)"
    fi

    # the user's api_key is not re-fetchable; read what add-user persisted.
    local key_file="$USER_DIR/$user.key" api_key=""
    [[ -s "$key_file" ]] || c_die "no saved api_key for user '$user' ($key_file); re-run add-user $user"
    api_key="$(cat "$key_file")"

    printf 'AUTHORITY_API_KEY=%s AUTHORITY_URL=%s ./operator.sh install %s\n' \
        "$api_key" "$AUTHORITY_URL" "$app_id"
}

# ════════════════════════════════════════════════════════════════════════════
usage() {
    cat <<EOF
vendor authority CLI

  launch [--launcher-image <ref>] [--os-version <v>]
  add-cek <name>
  enc-img --cek <name> --image-name <n> <src> <dst>
  add-user <username>
  add-app <appname> --image-name <n> [--usage <text>]
  grant-app --user <u> --app <appname|app-id>
  install-cmd --app <appname|app-id> --user <u>
EOF
}

main() {
    local cmd="${1:-}"
    [[ $# -gt 0 ]] && shift || true
    case "$cmd" in
        launch)       cmd_launch "$@" ;;
        add-cek)      cmd_add_cek "$@" ;;
        enc-img)      cmd_enc_img "$@" ;;
        add-user)     cmd_add_user "$@" ;;
        add-app)      cmd_add_app "$@" ;;
        grant-app)    cmd_grant_app "$@" ;;
        install-cmd)  cmd_install_cmd "$@" ;;
        ""|-h|--help|help) usage ;;
        *) c_die "unknown subcommand: $cmd (try --help)" ;;
    esac
}

main "$@"
