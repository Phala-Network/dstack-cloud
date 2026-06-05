<!-- SPDX-License-Identifier: Apache-2.0 -->
# on-prem-lite redesign — vendor/operator split, app-centric, SQLite

Replaces the mixed `scripts/` + single `config.env` with two clean role CLIs and an
app-centric authority. **This file is the implementation contract.**

## Premise (depends on Dstack-TEE/dstack#714 — new OS image)

With #714, a `key_provider=tpm` deployment may **pin a deploy-time `app_id`** (in
`.instance-info`), which is measured into RTMR3 as the attested `app_id`. So:

- **All apps share ONE launcher compose** (one `compose_hash` = "the trusted launcher
  build"); `app_id` is NOT in `app-compose.json`, so it doesn't affect `compose_hash`.
- **Each app = an authority-assigned random `app_id` (40 hex).** The operator deploys the
  shared compose with that `app_id` set → the CVM attests it. No per-app compose.
- The two measurements are **independent**: `compose_hash` gates *which launcher build*,
  `app_id` gates *which app*. The authority gates both.
- The lite **launcher binary is unchanged** (cr.kvin.wang/lite-launcher): it verifies the
  License sig + seq + validity + self `compose_hash`; it ignores License.app_id.

## Directory layout

```
on-prem-lite/
  deploy/
    vendor/     authority.sh        + (gitignored) .vendor-config   (AUTHORITY_URL, admin token, signing seed, pubkey)
    operator/   operator.sh         + (gitignored) config.env        (GCP project/zone/AR/IP/OS_VERSION, generated on first run)
    templates/  docker-compose.yaml.tmpl, app.json.tmpl, prelaunch.sh   (the single launcher build)
  authority/    FastAPI + SQLite
  launcher/     (unchanged Rust crate)
  REDESIGN.md DESIGN.md
```
The old `scripts/`, `deploy-templates/`, top-level `config.env` and `docker-compose.authority.yml`
retire into the above. `dstack-cloud` is referenced by repo-relative path
(resolve `…/scripts/bin/dstack-cloud` from the deploy dir).

## SQLite schema  (`/data/authority.db`, env `AUTHORITY_LITE_DB`)

```sql
tenants(user_id TEXT PRIMARY KEY, api_key_hash TEXT NOT NULL, created_at INT);
ceks(kid TEXT PRIMARY KEY, priv_pem TEXT NOT NULL, pub_pem TEXT NOT NULL, created_at INT);
images(id INTEGER PRIMARY KEY, image_name TEXT NOT NULL, dst_ref TEXT NOT NULL,
       digest TEXT NOT NULL, kid TEXT NOT NULL, created_at INT,
       UNIQUE(image_name, digest));                 -- latest = max(created_at) per image_name
-- the single trusted launcher build (one row; replace to roll a new launcher image)
launcher(id INTEGER PRIMARY KEY CHECK (id=1), compose_hash TEXT NOT NULL,
         app_compose_json TEXT NOT NULL, docker_compose TEXT NOT NULL,
         app_json TEXT NOT NULL, prelaunch TEXT NOT NULL,
         lite_launcher_dst TEXT NOT NULL, lite_launcher_digest TEXT NOT NULL, created_at INT);
apps(app_id TEXT PRIMARY KEY,                        -- authority-assigned random 40-hex
     app_name TEXT UNIQUE NOT NULL, image_name TEXT NOT NULL, usage_text TEXT, created_at INT);
grants(user_id TEXT, app_id TEXT, created_at INT, PRIMARY KEY(user_id, app_id));
licenses(id INTEGER PRIMARY KEY, user_id TEXT, app_id TEXT, seq INT, issued_at INT, expires_at INT);
os_images(hash TEXT PRIMARY KEY);                    -- G4 whitelist
```
`license_seq(user_id, app_id)` = `max(seq)+1` from `licenses`.
The set of registered launcher `compose_hash` (just `launcher.compose_hash`) is the G6 whitelist.

## Crypto / wire (UNCHANGED — keep byte-identical to current lite)

Ed25519 License over canonical JSON minus `authority_sig`; `sealed_cek` = base64(HPKE enc||ct),
DHKEM-X25519/HKDF-SHA256/AES-256-GCM, info=`b"dstack-lite-cek-v1"`; `report_data =
SHA-512(nonce ‖ transport_pub ‖ kms_ts_le)`. License fields unchanged (schema_version,
license_id, tenant_id, app_id, compose_hash, workload{image,digest,kid}, seq, issued_at,
not_before, expires_at, grace_period_secs, authority_sig). All gates FAIL-CLOSED; no
env-seed; admin/tenant endpoints refuse (503) without `AUTHORITY_ADMIN_TOKEN`.

## Authority endpoints

**Admin** (Bearer `AUTHORITY_ADMIN_TOKEN`; 503 if unset):
- `POST /api/v1/admin/ceks {kid}` → `{kid, pub_pem}`  ·  `GET /api/v1/admin/ceks`
- `POST /api/v1/admin/images {image_name, dst_ref, digest, kid}` → `{image_name, digest}`
- `GET  /api/v1/admin/images?image_name=` → `{versions:[…], latest_digest}`
- `POST /api/v1/admin/launcher {docker_compose, app_json, prelaunch, app_compose_json, lite_launcher_dst, lite_launcher_digest}`
       → authority computes `compose_hash=sha256(app_compose_json)`, stores the single launcher row, registers it as the G6 whitelist → `{compose_hash}`
- `POST /api/v1/admin/users {user_id}` → `{user_id, api_key}`
- `POST /api/v1/admin/apps {app_name, image_name, usage_text?}` → authority assigns a random
       40-hex `app_id`, stores → `{app_id}`
- `POST /api/v1/admin/grants {user_id, app}` (app = app_name or app_id) → `{user_id, app_id}`
- `POST /api/v1/admin/os-images {hash}` · `GET` · `DELETE /{hash}`

**Tenant** (Bearer tenant api_key; 503 if no admin token configured):
- `POST /api/v1/challenge {user_id}` → `{nonce, authority_ts}`
- `GET  /api/v1/app/{app_id}/bundle`  (tenant must be granted app_id) →
  ```json
  { "app_id","app_name",
    "docker_compose","app_json","prelaunch",   // the single launcher build; operator writes these + sets app_id
    "compose_hash","authority_pubkey",
    "lite_launcher": {"dst_ref","digest"},
    "workload":      {"image_name","dst_ref","digest"},  // image_name's latest version
    "usage_text" }
  ```
- `POST /api/v1/license {user_id, app_id, workload_image, nonce, transport_pub, kms_ts, attestation, vm_config, workload_digest?}` → `{license, sealed_cek}`
  Gates (fail-closed): quote(G1) · report_data(G2) · tcb(G3) · os_image∈os_images(G4) ·
  key_provider==tpm(G5) · **attested compose_hash == launcher.compose_hash**(G6) ·
  **attested app_id == request.app_id == a registered app**, **tenant granted that app_id**(G6b) ·
  `workload_digest` (default: the app's image latest) ∈ that image's registered versions(G7,
  registry-agnostic — gated by digest, not by registry prefix). The matched version's `kid` →
  seal that CEK. `License.app_id = app_id`, `compose_hash = launcher.compose_hash`,
  `workload = {image: workload_image, digest: workload_digest, kid}`.
  `workload_image` is the **operator's AR ref** for the image (the operator knows its own AR;
  the digest is the security anchor, so the registry prefix is not gated). This keeps the
  **current launcher unchanged** (it pulls `image@digest`).
- `GET /api/v1/authority-pubkey` → `{pubkey}`

> The operator passes `workload_image=<AR>/<image_name>` in the license request (operator.sh
> derives it from `config.env` AR + the bundle's `workload.image_name`). The authority signs it
> verbatim after gating the digest. No launcher change.

## Vendor CLI — `deploy/vendor/authority.sh`

Persists `.vendor-config` (sourced each run): AUTHORITY_URL, AUTHORITY_ADMIN_TOKEN,
AUTHORITY_NONCE_SECRET, AUTHORITY_SIGNING_KEY, AUTHORITY_PUBKEY, PUBREG, OS_VERSION,
LITE_LAUNCHER_REF.

- `launch [--launcher-image <ref>] [--os-version <v>]` — `docker compose up -d --build` the
  authority+verifier; first run: generate + persist admin token / nonce secret / signing seed;
  fetch + persist AUTHORITY_PUBKEY. Then **set up the launcher build**: render
  `templates/*` (pin `lite-launcher@<digest>` + literal AUTHORITY_PUBKEY), `dstack-cloud prepare`
  → `compose_hash`; `POST /admin/launcher`. Print AUTHORITY_PUBKEY + the launcher compose_hash.
- `add-cek <name>` → `POST /admin/ceks {kid:name}`.
- `enc-img --cek <name> --image-name <n> <src> <dst>` — `skopeo copy --encryption-key
  jwe:<cek pub> docker://<src> docker://<dst>`; `skopeo inspect` digest;
  `POST /admin/images {image_name:n, dst_ref:dst, digest, kid:name}`.
- `add-user <username>` → `POST /admin/users` → print the api_key (deliver to operator).
- `add-app <appname> --image-name <n> [--usage <text>]` → `POST /admin/apps` → print app_id.
- `grant-app --user <u> --app <appname|app-id>` → `POST /admin/grants`.
- `install-cmd --app <appname|app-id> --user <u>` → resolve app_id + the user's api_key; print:
  `AUTHORITY_API_KEY=<key> AUTHORITY_URL=<url> ./operator.sh install <app-id>`

## Operator CLI — `deploy/operator/operator.sh`

- `install <app-id>` (env `AUTHORITY_API_KEY`, `AUTHORITY_URL`):
  1. `GET /app/<app-id>/bundle`. If `config.env` missing → write a template
     (GCP_PROJECT/ZONE/AR_*/WORKLOAD_IP/OS_VERSION) and exit asking to edit + re-run.
  2. Write the deploy dir from the bundle (`docker_compose`,`app_json`,`prelaunch`); **set
     `app_json.app_id = <app-id>`** + GCP fields + `.user-config {DSTACK_REGISTRY:<AR>}`.
  3. `sync` the two images (lite_launcher, workload) bundle.dst_ref→AR (digest-preserving skopeo).
  4. `dstack-cloud prepare && deploy`; `fw allow 9000`.  (assert local compose_hash == bundle.compose_hash)
  5. courier: challenge → courier/init → license(app_id=<app-id>) → courier/install.
  6. Print `usage_text`.
- `sync <app-id>` — step 3 only.
- `update <app-id>` — re-run license (renew / pick up the image's new latest digest; rolling update).
- `status` / `healthz` — IAP-tunnel to the launcher `/status` / `/healthz` (free-port guard).
Uses repo-relative `dstack-cloud`.

## Security recap
`compose_hash`(G6) = trusted launcher build (can't be faked — it's the real measurement);
`app_id`(G6b) = operator-set label, gated by tenant grant + the app's image whitelist + the
CEK being sealed to the attested transport key. An operator forging `app_id=X` only gets CEKs
for images in app X **if** granted X. TLS for a remote AUTHORITY_URL is the vendor's job (doc it).
