# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0
"""on-prem-lite vendor authority (KMS-less, license-based, app-centric).

Issues a per-workload {sealed_cek, License} to an attested launcher CVM:
verifies the launcher's TDX+vTPM quote via dstack-verifier (fail-closed gates),
HPKE-seals the image private key (CEK) to the launcher's transport key, and
Ed25519-signs a License with an expiry. See on-prem-lite/REDESIGN.md for the
wire contract; a Rust launcher verifies the License signature and HPKE-opens the
CEK.

Model: all apps share ONE launcher build (one compose_hash). Each app is an
authority-assigned random 40-hex app_id deployed (deploy-time) into that shared
launcher; the CVM attests it. The authority gates BOTH the launcher build
(compose_hash, G6) and the app (attested app_id == request app_id == registered
app, tenant granted, G6b), then gates the workload digest against the app's image
whitelist (G7) and seals that version's CEK.
"""

import base64
import hashlib
import json
import logging
import os
import time
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException

from crypto import (
    get_authority_pubkey_bytes,
    issue_challenge,
    seal_cek,
    sign_license,
    verify_challenge,
)
from models import (
    AddImageRequest,
    AddImageResponse,
    ChallengeRequest,
    ChallengeResponse,
    CreateAppRequest,
    CreateAppResponse,
    CreateUserRequest,
    CreateUserResponse,
    GrantRequest,
    GrantResponse,
    HashRequest,
    LicenseRequest,
    LicenseResponse,
    MintCekRequest,
    MintCekResponse,
    SetLauncherRequest,
    SetLauncherResponse,
)
from store import Store
from verifier_client import VerifierError, compute_report_data, verify_attestation

logger = logging.getLogger(__name__)

app = FastAPI(title="dstack on-prem-lite authority", version="0.2.0")
store = Store()

# ─── auth ─────────────────────────────────────────────────────────────────────
# admin endpoints are gated by AUTHORITY_ADMIN_TOKEN; tenant endpoints
# (challenge / bundle / license) require a per-tenant bearer API key. The admin
# token is REQUIRED — without it the authority refuses to serve (fail-closed):
# there is no open/dev mode in this profile.
ADMIN_TOKEN = os.getenv("AUTHORITY_ADMIN_TOKEN", "")

# Attestation verification via the repo's dstack-verifier service. A license is
# ALWAYS issued against a verified quote — there is no no-attestation bypass.
VERIFIER_URL = os.getenv("VERIFIER_URL", "http://verifier:8080")
ALLOWED_TCB_STATUSES = {
    s.strip() for s in os.getenv("ALLOWED_TCB_STATUSES", "UpToDate,SWHardeningNeeded").split(",") if s.strip()
}
# License expiry policy.
LICENSE_TTL_SECS = int(os.getenv("LICENSE_TTL_SECS", str(86400 * 30)))   # 30d
LICENSE_GRACE_SECS = int(os.getenv("LICENSE_GRACE_SECS", "300"))

if not ADMIN_TOKEN:
    logger.warning("AUTHORITY_ADMIN_TOKEN unset — admin + tenant endpoints are FAIL-CLOSED "
                   "(refused with 503) until it is set")


def _bearer(authorization: Optional[str]) -> str:
    if not authorization:
        return ""
    parts = authorization.split(None, 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip()
    return authorization.strip()


def require_admin(authorization: Optional[str] = Header(None)) -> None:
    """Gate admin endpoints behind the authority admin token. FAIL-CLOSED: if no
    token is configured, admin endpoints are refused (no open/dev mode)."""
    if not ADMIN_TOKEN:
        raise HTTPException(status_code=503,
                            detail="authority admin token not configured (fail-closed); set AUTHORITY_ADMIN_TOKEN")
    import hmac
    if not hmac.compare_digest(_bearer(authorization), ADMIN_TOKEN):
        raise HTTPException(status_code=401, detail="invalid admin token")


def resolve_tenant(req_user_id: str, authorization: Optional[str]) -> str:
    """Resolve the calling tenant from its bearer API key. The request's user_id,
    if given, must match the authenticated tenant (strict isolation). FAIL-CLOSED:
    a tenant API key is always required (no token ⇒ refuse; no dev trust-user_id)."""
    if not ADMIN_TOKEN:
        raise HTTPException(status_code=503,
                            detail="authority not configured for tenants (fail-closed); set AUTHORITY_ADMIN_TOKEN")
    tid = store.find_tenant_by_api_key(_bearer(authorization))
    if tid is None:
        raise HTTPException(status_code=401, detail="invalid or missing api key")
    if req_user_id and req_user_id != tid:
        raise HTTPException(
            status_code=403,
            detail=f"user_id '{req_user_id}' does not match authenticated tenant '{tid}'",
        )
    return tid


@app.get("/api/v1/authority-pubkey")
def authority_pubkey():
    """Return the authority Ed25519 public key.

    The vendor pins this into the measured launcher compose (AUTHORITY_PUBKEY)
    so the launcher can verify License signatures offline.
    """
    return {"pubkey": base64.b64encode(get_authority_pubkey_bytes()).decode()}


# ─── tenant: challenge ────────────────────────────────────────────────────────

@app.post("/api/v1/challenge", response_model=ChallengeResponse)
def challenge(req: ChallengeRequest, authorization: Optional[str] = Header(None)):
    """Issue a stateless (HMAC) challenge nonce for the courier attest flow."""
    tenant_id = resolve_tenant(req.user_id, authorization)  # authenticates caller
    nonce = issue_challenge(tenant_id)
    return ChallengeResponse(nonce=nonce, authority_ts=int(time.time()))


# ─── tenant: bundle ───────────────────────────────────────────────────────────

@app.get("/api/v1/app/{app_id}/bundle")
def app_bundle(app_id: str, authorization: Optional[str] = Header(None)):
    """Return the deploy bundle for an app the tenant is granted: the single
    launcher build (docker_compose/app_json/prelaunch + compose_hash), the
    authority pubkey, the lite-launcher ref/digest, and the app's image_name +
    its latest registered version (dst_ref + digest)."""
    tenant_id = resolve_tenant("", authorization)
    app_id = (app_id or "").lower()
    if not store.is_granted(tenant_id, app_id):
        raise HTTPException(status_code=403,
                            detail=f"tenant '{tenant_id}' not granted app {app_id}")
    app_rec = store.get_app_by_id(app_id)
    if app_rec is None:
        raise HTTPException(status_code=404, detail=f"app not found: {app_id}")
    launcher = store.get_launcher()
    if launcher is None:
        raise HTTPException(status_code=503,
                            detail="no launcher build registered (fail-closed); vendor must POST /admin/launcher")
    image_name = app_rec["image_name"]
    latest = store.get_image_latest(image_name)
    if latest is None:
        raise HTTPException(status_code=503,
                            detail=f"no registered image version for {image_name} (fail-closed)")
    return {
        "app_id": app_rec["app_id"],
        "app_name": app_rec["app_name"],
        "docker_compose": launcher["docker_compose"],
        "app_json": launcher["app_json"],
        "prelaunch": launcher["prelaunch"],
        "compose_hash": launcher["compose_hash"],
        "authority_pubkey": base64.b64encode(get_authority_pubkey_bytes()).decode(),
        "lite_launcher": {
            "dst_ref": launcher["lite_launcher_dst"],
            "digest": launcher["lite_launcher_digest"],
        },
        "workload": {
            "image_name": image_name,
            "dst_ref": latest["dst_ref"],
            "digest": latest["digest"],
        },
        "usage_text": app_rec.get("usage_text") or "",
    }


def _verify_launcher_attestation(req: LicenseRequest, tenant_id: str) -> tuple:
    """Verify the launcher's TDX+vTPM attestation and enforce the fail-closed
    gates G1–G6b. Returns (attested_app_id, attested_compose_hash), both
    lowercased. Raises HTTPException on any policy failure.
    """
    # FAIL-CLOSED: an attestation is always required — there is no dev/no-quote
    # bypass. A license is only ever issued against a verified TDX+vTPM quote.
    attestation = (req.attestation or "").strip()
    if not attestation:
        raise HTTPException(status_code=400, detail="attestation required (fail-closed)")

    # os-image whitelist is FAIL-CLOSED (G4, enforced below). When exactly one is
    # configured, inject it into vm_config so the verifier can pin it; with
    # several, the membership check below is the gate.
    allowed_os = store.get_os_images()
    vm_config = req.vm_config
    if len(allowed_os) == 1:
        try:
            cfg = json.loads(vm_config) if vm_config else {}
        except (ValueError, TypeError):
            cfg = {}
        cfg["os_image_hash"] = allowed_os[0]
        vm_config = json.dumps(cfg)

    try:
        result = verify_attestation(VERIFIER_URL, attestation, vm_config)
    except VerifierError as e:
        raise HTTPException(status_code=502, detail=str(e))

    details = result.get("details", {})
    app_info = details.get("app_info") or {}
    logger.info(
        "verifier[%s]: is_valid=%s quote=%s eventlog=%s os_image=%s tcb=%s "
        "compose=%s app_id=%s kp_info=%s reason=%s",
        tenant_id, result.get("is_valid"), details.get("quote_verified"),
        details.get("event_log_verified"), details.get("os_image_hash_verified"),
        details.get("tcb_status"), app_info.get("compose_hash"),
        app_info.get("app_id"), app_info.get("key_provider_info"), result.get("reason"),
    )

    # G1: the TDX(+vTPM) quote must be authentic (hardware-rooted).
    if not details.get("quote_verified"):
        raise HTTPException(status_code=403, detail=f"quote verification failed: {result.get('reason')}")

    # G2: report_data must bind this session's transport key/nonce (anti-substitution).
    expected = compute_report_data(req.nonce, req.transport_pub, req.kms_ts).hex()
    got = (details.get("report_data") or "").lower()
    if got != expected.lower():
        raise HTTPException(status_code=403,
                            detail="report_data mismatch: quote not bound to this transport key/nonce")

    # G3: TCB status must be acceptable (empty/missing ⇒ deny).
    tcb = details.get("tcb_status")
    if tcb not in ALLOWED_TCB_STATUSES:
        raise HTTPException(status_code=403, detail=f"unacceptable tcb_status: {tcb}")

    # G4: os-image hash — FAIL-CLOSED (empty whitelist ⇒ deny). Register the
    # vendor-approved os_image_hash via POST /api/v1/admin/os-images.
    if not allowed_os:
        raise HTTPException(status_code=403,
                            detail="no approved os_image_hash (fail-closed; register one via "
                                   "POST /api/v1/admin/os-images)")
    if not details.get("os_image_hash_verified"):
        raise HTTPException(status_code=403,
                            detail=f"os_image_hash not verified: {result.get('reason')}")
    os_hash = (app_info.get("os_image_hash") or "").lower()
    if os_hash not in allowed_os:
        raise HTTPException(status_code=403,
                            detail=f"os_image_hash not in whitelist: {os_hash or 'none'}")

    # G5: key_provider must be tpm (vTPM-sealed disk). key_provider_info is the
    # hex of JSON {"name": "<none|local-sgx|tpm|kms>", "id": "<pubkey>"}.
    kp_name = ""
    kp_hex = app_info.get("key_provider_info") or ""
    if kp_hex:
        try:
            kp_name = (json.loads(bytes.fromhex(kp_hex).decode()) or {}).get("name", "")
        except (ValueError, TypeError):
            kp_name = ""
    if kp_name != "tpm":
        raise HTTPException(status_code=403,
                            detail=f"key_provider must be tpm, got '{kp_name or 'unknown'}'")

    # G6: launcher compose_hash == the single registered launcher build's
    # compose_hash (fail-closed: no launcher registered ⇒ deny).
    compose_hash = (app_info.get("compose_hash") or "").lower()
    if not compose_hash:
        raise HTTPException(status_code=403, detail="compose_hash missing from attestation")
    launcher = store.get_launcher()
    if launcher is None:
        raise HTTPException(status_code=403,
                            detail="no registered launcher build (fail-closed; vendor must "
                                   "POST /api/v1/admin/launcher)")
    if compose_hash != (launcher["compose_hash"] or "").lower():
        raise HTTPException(status_code=403, detail="compose_hash does not match the registered launcher build")

    # G6b: app_id. With #714 the attested app_id is a deploy-time-pinned measured
    # value. We require: attested app_id == request app_id, the app is registered,
    # and the tenant is granted it. (The measured launcher build is gated by G6.)
    attested_app_id = (app_info.get("app_id") or "").lower()
    req_app_id = (req.app_id or "").lower()
    if not req_app_id:
        raise HTTPException(status_code=403, detail="app_id required")
    if attested_app_id != req_app_id:
        raise HTTPException(status_code=403,
                            detail=f"attested app_id '{attested_app_id or 'none'}' != request app_id '{req_app_id}'")
    if store.get_app_by_id(req_app_id) is None:
        raise HTTPException(status_code=403, detail=f"app_id not registered: {req_app_id}")
    if not store.is_granted(tenant_id, req_app_id):
        raise HTTPException(status_code=403,
                            detail=f"tenant '{tenant_id}' not granted app {req_app_id}")

    logger.info("license %s: gates OK (quote✓ report_data✓ tcb✓ key_provider=tpm✓ "
                "compose_hash✓ app_id=%s)", tenant_id, req_app_id)
    return req_app_id, compose_hash


@app.post("/api/v1/license", response_model=LicenseResponse)
def license(req: LicenseRequest, authorization: Optional[str] = Header(None)):
    """Verify the launcher attestation and return a {sealed_cek, signed License}.

    The core endpoint: gates G1–G7 (fail-closed), then HPKE-seals the image
    private key (CEK) to the launcher transport key and Ed25519-signs a License
    with a monotonic seq + expiry.
    """
    tenant_id = resolve_tenant(req.user_id, authorization)

    # validate the stateless challenge nonce (authentic MAC, within TTL, bound to
    # this tenant). The TDX-quote report_data binding is the real anti-replay.
    if not verify_challenge(req.nonce, tenant_id):
        raise HTTPException(status_code=400, detail="invalid or expired nonce")

    # clock-skew guard between authority and launcher.
    skew = abs(req.kms_ts - int(time.time()))
    if skew > 300:
        raise HTTPException(status_code=400, detail=f"clock skew too large: {skew}s")

    if not req.transport_pub:
        raise HTTPException(status_code=400, detail="transport_pub required")
    if not req.workload_image:
        raise HTTPException(status_code=400, detail="workload_image required")

    # G1–G6b: verify attestation; returns the validated app_id + the launcher's
    # measured compose_hash (bound into the License so the launcher can check it
    # equals its own).
    app_id, attested_compose_hash = _verify_launcher_attestation(req, tenant_id)

    app_rec = store.get_app_by_id(app_id)   # exists (checked in G6b)
    image_name = app_rec["image_name"]

    # G7: resolve the workload digest. Default = the app's image latest. The digest
    # must be a registered version of THIS app's image (registry-agnostic — gated
    # by digest membership, not by registry prefix). The matched version carries
    # the kid → CEK to seal.
    workload_digest = (req.workload_digest or "").strip()
    if not workload_digest:
        latest = store.get_image_latest(image_name)
        if latest is None:
            raise HTTPException(status_code=403,
                                detail=f"no registered image version for {image_name} (fail-closed)")
        workload_digest = latest["digest"]
    version = store.find_image_by_digest(image_name, workload_digest)
    if version is None:
        raise HTTPException(status_code=403,
                            detail=f"workload_digest not a registered version of {image_name}: {workload_digest}")

    # HPKE-seal the matched version's CEK (its private key PEM) to the launcher
    # transport key.
    kid = version["kid"]
    cek = store.get_cek(kid)
    if cek is None:
        raise HTTPException(status_code=500, detail=f"cek not found for kid: {kid}")
    sealed_cek = seal_cek(cek["priv_pem"], req.transport_pub)

    # build + Ed25519-sign the License.
    now = int(time.time())
    seq = store.bump_license_seq(tenant_id, app_id)
    expires_at = now + LICENSE_TTL_SECS
    license_obj = {
        "schema_version": 1,
        "license_id": f"{tenant_id}-{seq}",
        "tenant_id": tenant_id,
        "app_id": app_id,
        # the launcher's measured compose (which launcher build); the launcher
        # additionally checks license.compose_hash == its own.
        "compose_hash": attested_compose_hash,
        "workload": {
            # operator's AR ref, signed verbatim; the digest is the security anchor.
            "image": req.workload_image,
            "digest": workload_digest,
            "kid": kid,
        },
        "seq": seq,
        "issued_at": now,
        "not_before": now,
        "expires_at": expires_at,
        "grace_period_secs": LICENSE_GRACE_SECS,
    }
    license_obj["authority_sig"] = sign_license(license_obj)
    store.record_license_expiry(tenant_id, app_id, seq, expires_at)

    logger.info("issued license %s seq=%d app=%s image=%s digest=%s kid=%s expires_at=%d",
                license_obj["license_id"], seq, app_id, image_name, workload_digest, kid, expires_at)
    return LicenseResponse(license=license_obj, sealed_cek=sealed_cek)


# ─── admin: ceks ──────────────────────────────────────────────────────────────

@app.post("/api/v1/admin/ceks", response_model=MintCekResponse)
def mint_cek(req: MintCekRequest, _: None = Depends(require_admin)):
    """Mint an EC P-256 content-encryption keypair (CEK). Returns the PUBLIC key
    — encrypt images to it with `skopeo copy --encryption-key jwe:<pub.pem>`. The
    private key is never returned by the API."""
    try:
        entry = store.mint_cek((req.kid or "").strip())
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    logger.info("minted cek kid=%s", entry["kid"])
    return MintCekResponse(kid=entry["kid"], pub_pem=entry["pub_pem"])


@app.get("/api/v1/admin/ceks")
def list_ceks(_: None = Depends(require_admin)):
    """List ceks (kid + public key; private keys are never echoed)."""
    return {"ceks": store.list_ceks()}


# ─── admin: images ────────────────────────────────────────────────────────────

@app.post("/api/v1/admin/images", response_model=AddImageResponse)
def add_image(req: AddImageRequest, _: None = Depends(require_admin)):
    """Register an (image_name, dst_ref, digest, kid) version. latest = newest."""
    try:
        entry = store.add_image_version(req.image_name, req.dst_ref, req.digest, req.kid)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    logger.info("registered image %s@%s kid=%s", req.image_name, req.digest, req.kid)
    return AddImageResponse(image_name=entry["image_name"], digest=entry["digest"])


@app.get("/api/v1/admin/images")
def list_images(image_name: str, _: None = Depends(require_admin)):
    """List the registered versions of image_name + its latest digest."""
    versions = store.get_image_versions(image_name)
    latest = store.get_image_latest(image_name)
    return {"versions": versions, "latest_digest": latest["digest"] if latest else None}


# ─── admin: launcher (the single trusted build) ───────────────────────────────

@app.post("/api/v1/admin/launcher", response_model=SetLauncherResponse)
def set_launcher(req: SetLauncherRequest, _: None = Depends(require_admin)):
    """Store the single launcher build. The authority computes
    compose_hash=sha256(app_compose_json) and registers it as the G6 whitelist
    (replacing any prior launcher build)."""
    compose_hash = hashlib.sha256(req.app_compose_json.encode()).hexdigest()
    store.set_launcher(
        compose_hash=compose_hash,
        app_compose_json=req.app_compose_json,
        docker_compose=req.docker_compose,
        app_json=req.app_json,
        prelaunch=req.prelaunch,
        lite_launcher_dst=req.lite_launcher_dst,
        lite_launcher_digest=req.lite_launcher_digest,
    )
    logger.info("registered launcher build compose_hash=%s", compose_hash)
    return SetLauncherResponse(compose_hash=compose_hash)


# ─── admin: users (tenants) ───────────────────────────────────────────────────

@app.post("/api/v1/admin/users", response_model=CreateUserResponse)
def create_user(req: CreateUserRequest, _: None = Depends(require_admin)):
    """Create a tenant (operator account). Returns the API key in plaintext once."""
    try:
        api_key = store.create_tenant(req.user_id)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    logger.info("created user user_id=%s", req.user_id)
    return CreateUserResponse(user_id=req.user_id, api_key=api_key)


# ─── admin: apps ──────────────────────────────────────────────────────────────

@app.post("/api/v1/admin/apps", response_model=CreateAppResponse)
def create_app(req: CreateAppRequest, _: None = Depends(require_admin)):
    """Register an app: authority assigns a random 40-hex app_id, binds it to an
    image_name + usage_text."""
    try:
        app_id = store.create_app(req.app_name, req.image_name, req.usage_text or "")
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    logger.info("created app app_name=%s app_id=%s image=%s", req.app_name, app_id, req.image_name)
    return CreateAppResponse(app_id=app_id)


@app.get("/api/v1/admin/apps")
def list_apps(_: None = Depends(require_admin)):
    """List apps (app_id + app_name + image_name) — used by `install-cmd` to
    resolve an app_name → app_id."""
    return {"apps": store.list_apps()}


# ─── admin: grants ────────────────────────────────────────────────────────────

@app.post("/api/v1/admin/grants", response_model=GrantResponse)
def grant_app(req: GrantRequest, _: None = Depends(require_admin)):
    """Authorize a tenant for an app (app = app_name or app_id)."""
    app_rec = store.get_app(req.app)
    if app_rec is None:
        raise HTTPException(status_code=404, detail=f"unknown app: {req.app}")
    try:
        store.grant(req.user_id, app_rec["app_id"])
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    logger.info("granted user=%s app=%s", req.user_id, app_rec["app_id"])
    return GrantResponse(user_id=req.user_id, app_id=app_rec["app_id"])


# ─── admin: os-image policy (G4) ──────────────────────────────────────────────

@app.post("/api/v1/admin/os-images")
def add_os_image(req: HashRequest, _: None = Depends(require_admin)):
    """Approve an os-image hash (G4 whitelist; fail-closed when empty)."""
    try:
        lst = store.add_os_image(req.hash)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    logger.info("approved os_image hash %s", req.hash)
    return {"os_images": lst}


@app.get("/api/v1/admin/os-images")
def list_os_images(_: None = Depends(require_admin)):
    return {"os_images": store.get_os_images()}


@app.delete("/api/v1/admin/os-images/{h}")
def remove_os_image(h: str, _: None = Depends(require_admin)):
    if not store.remove_os_image(h):
        raise HTTPException(status_code=404, detail=f"os_image hash not found: {h}")
    logger.info("removed os_image hash %s", h)
    return {"os_images": store.get_os_images()}
