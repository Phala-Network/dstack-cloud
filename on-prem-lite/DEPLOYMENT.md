<!-- SPDX-License-Identifier: Apache-2.0 -->
# on-prem-lite deployment guide

A role-split runbook for the **KMS-less single-CVM** profile. The **vendor** runs an
Authority, ships an encrypted workload image, and registers one measured launcher
build (one `compose_hash` shared by all apps). The **operator** deploys one workload
CVM, attests it, and installs a License over an IAP courier hop. See
[DESIGN.md](DESIGN.md) for the protocol and the fail-closed gate table, and
[REDESIGN.md](REDESIGN.md) for the app-centric authority contract.

Two CLIs, one per role:

- vendor: `deploy/vendor/authority.sh` (persists `.vendor-config`)
- operator: `deploy/operator/operator.sh` (persists `config.env`)

The shared launcher build lives in `deploy/templates/` and is rendered identically
by both sides (`dstack-cloud prepare` → same `compose_hash`).

---

## Vendor

Run from `on-prem-lite/deploy/vendor/`. First `launch` generates + persists the
signing seed, admin token, nonce secret, and the Authority pubkey into
`.vendor-config` (gitignored).

```bash
# 1. start authority + verifier; render templates/* (pin lite-launcher@digest +
#    literal AUTHORITY_PUBKEY); prepare → compose_hash; register the launcher build.
./authority.sh launch --launcher-image cr.kvin.wang/lite-launcher:latest \
                      --os-version dstack-cloud-nvidia-0.6.1

# 2. mint a global image-encryption keypair (CEK).
./authority.sh add-cek vendor-keyring

# 3. encrypt the workload image (JWE to the CEK pubkey) and register it.
./authority.sh enc-img --cek vendor-keyring --image-name whoami-lite \
                      docker.io/acme/whoami:latest cr.kvin.wang/whoami-lite-enc:latest

# 4. create a tenant (operator) — prints the api_key ONCE; deliver to the operator.
./authority.sh add-user acme-corp

# 5. register an app (authority assigns a random 40-hex app_id) bound to the image.
./authority.sh add-app whoami --image-name whoami-lite --usage "curl http://<ip>:8080"

# 6. grant the tenant access to the app.
./authority.sh grant-app --user acme-corp --app whoami

# 7. print the operator's one-line install command (resolves app_id + api_key).
./authority.sh install-cmd --app whoami --user acme-corp
```

Step 7 prints something like:

```
AUTHORITY_API_KEY=… AUTHORITY_URL=https://authority.acme.example ./operator.sh install <app-id>
```

> **TLS is the vendor's job.** `AUTHORITY_URL` must be HTTPS when the operator is
> remote — terminate TLS in front of the Authority (reverse proxy / managed cert).
> The courier carries only opaque blobs, but the api_key is a Bearer credential.

---

## Operator

Run from `on-prem-lite/deploy/operator/`. Paste the vendor's printed command:

```bash
AUTHORITY_API_KEY=… AUTHORITY_URL=https://authority.acme.example \
    ./operator.sh install <app-id>
```

First run fetches the bundle, then writes a commented `config.env` and exits asking
you to fill it:

```bash
# edit config.env: GCP_PROJECT, GCP_ZONE, AR_LOCATION/AR_PROJECT/AR_REPO,
#                  WORKLOAD_IP, OS_VERSION
$EDITOR config.env

# re-run the same command — it now runs end to end:
AUTHORITY_API_KEY=… AUTHORITY_URL=https://authority.acme.example \
    ./operator.sh install <app-id>
```

`install` does, in order:

1. `GET /api/v1/app/<app-id>/bundle` (Bearer api_key).
2. write `deploy-work/` from the bundle (`docker_compose`, `app_json`, `prelaunch`);
   set `app_json.app_id=<app-id>` + GCP fields + `.user-config {DSTACK_REGISTRY:<AR>}`.
3. sync the two images (lite-launcher + workload) bundle→AR with digest-preserving
   skopeo; pull the OS image.
4. `dstack-cloud prepare && deploy`; assert local `compose_hash == bundle.compose_hash`
   (die on mismatch); `fw allow 9000`.
5. courier over an IAP tunnel: challenge → courier/init → license → courier/install.
6. print the app's `usage_text`.

Day-2 / other subcommands:

```bash
./operator.sh sync   <app-id>   # re-sync the bundle's images into your AR (step 3 only)
./operator.sh update <app-id>   # re-run the license flow (renew / rolling update)
./operator.sh status            # IAP-tunnel → launcher /status
./operator.sh healthz           # IAP-tunnel → launcher /healthz
```

The workload image's registry prefix is **not** gated by the Authority — only the
digest is (the security anchor). The operator passes its own AR ref
(`<AR>/<image_name>`) as `workload_image`; the Authority signs it verbatim after
gating the digest, so the unchanged launcher pulls `image@digest` from the AR.
