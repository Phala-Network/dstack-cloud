# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0
"""Request/response models for the on-prem-lite authority (app-centric model)."""

from pydantic import BaseModel
from typing import Any, Dict, List, Optional


# ─── challenge ────────────────────────────────────────────────────────────────

class ChallengeRequest(BaseModel):
    user_id: str


class ChallengeResponse(BaseModel):
    nonce: str
    authority_ts: int


# ─── license (the core endpoint) ──────────────────────────────────────────────

class LicenseRequest(BaseModel):
    user_id: str
    app_id: str                          # which app (must == attested app_id, granted)
    workload_image: str                  # operator's AR ref (signed verbatim; digest is the anchor)
    nonce: str
    transport_pub: str                   # base64 X25519 32 bytes
    kms_ts: int
    attestation: str = ""                # hex dstack VersionedAttestation (TDX+vTPM)
    vm_config: Optional[str] = None      # for dstack-verifier os_image_hash check
    workload_digest: Optional[str] = None  # requested image digest (default: app image latest)


class LicenseResponse(BaseModel):
    license: Dict[str, Any]              # signed License object
    sealed_cek: str                      # base64 HPKE-sealed image private key PEM


# ─── admin: ceks ──────────────────────────────────────────────────────────────

class MintCekRequest(BaseModel):
    kid: Optional[str] = ""              # key id; random hex if omitted


class MintCekResponse(BaseModel):
    kid: str
    pub_pem: str                         # PEM public key — encrypt with: skopeo --encryption-key jwe:<file>


# ─── admin: images ────────────────────────────────────────────────────────────

class AddImageRequest(BaseModel):
    image_name: str
    dst_ref: str
    digest: str
    kid: str


class AddImageResponse(BaseModel):
    image_name: str
    digest: str


# ─── admin: launcher (the single trusted build) ───────────────────────────────

class SetLauncherRequest(BaseModel):
    docker_compose: str
    app_json: str
    prelaunch: str
    app_compose_json: str                # authority computes compose_hash=sha256(this)
    lite_launcher_dst: str
    lite_launcher_digest: str


class SetLauncherResponse(BaseModel):
    compose_hash: str


# ─── admin: users (tenants) ───────────────────────────────────────────────────

class CreateUserRequest(BaseModel):
    user_id: str


class CreateUserResponse(BaseModel):
    user_id: str
    api_key: str               # plaintext — shown only once at creation
    note: str = "store this api_key now; it is not retrievable later"


# ─── admin: apps ──────────────────────────────────────────────────────────────

class CreateAppRequest(BaseModel):
    app_name: str
    image_name: str
    usage_text: Optional[str] = ""


class CreateAppResponse(BaseModel):
    app_id: str                          # authority-assigned random 40-hex


# ─── admin: grants ────────────────────────────────────────────────────────────

class GrantRequest(BaseModel):
    user_id: str
    app: str                             # app_name or app_id


class GrantResponse(BaseModel):
    user_id: str
    app_id: str


# ─── admin: os-images (G4 whitelist) ──────────────────────────────────────────

class HashRequest(BaseModel):
    hash: str                            # an os-image measurement hash
