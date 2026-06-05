# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0
"""SQLite-backed store for the on-prem-lite authority (app-centric model).

A single SQLite database (env AUTHORITY_LITE_DB, default
~/.config/authority-lite/authority.db) holds the whole vendor/operator state:

  tenants    — operator accounts (user_id + hashed api_key)
  ceks       — content-encryption keypairs (kid → EC P-256 priv/pub PEM)
  images     — per-image registered versions (image_name, dst_ref, digest, kid);
               latest = max(created_at) per image_name
  launcher   — the SINGLE trusted launcher build (one row, id=1); its compose_hash
               is the G6 whitelist
  apps       — authority-assigned random 40-hex app_id → (app_name, image_name)
  grants     — (user_id, app_id) tenant→app authorizations
  licenses   — issued license ledger; license_seq(user, app) = max(seq)+1
  os_images  — approved os-image hashes (G4 whitelist)

Uses the stdlib sqlite3 (no ORM), WAL journaling, tables created on first open.
Challenge nonces stay stateless (HMAC, see crypto.issue_challenge), so nothing
nonce-related is kept here.
"""

import hashlib
import os
import secrets
import sqlite3
import time
from typing import Any, Dict, List, Optional

from crypto import (
    generate_keypair,
    generate_api_key,
    hash_api_key,
    api_key_matches,
)

_DB_PATH = os.path.expanduser(
    os.getenv("AUTHORITY_LITE_DB", "~/.config/authority-lite/authority.db")
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS tenants (
    user_id      TEXT PRIMARY KEY,
    api_key_hash TEXT NOT NULL,
    created_at   INT
);
CREATE TABLE IF NOT EXISTS ceks (
    kid        TEXT PRIMARY KEY,
    priv_pem   TEXT NOT NULL,
    pub_pem    TEXT NOT NULL,
    created_at INT
);
CREATE TABLE IF NOT EXISTS images (
    id         INTEGER PRIMARY KEY,
    image_name TEXT NOT NULL,
    dst_ref    TEXT NOT NULL,
    digest     TEXT NOT NULL,
    kid        TEXT NOT NULL,
    created_at INT,
    UNIQUE(image_name, digest)
);
CREATE TABLE IF NOT EXISTS launcher (
    id                   INTEGER PRIMARY KEY CHECK (id = 1),
    compose_hash         TEXT NOT NULL,
    app_compose_json     TEXT NOT NULL,
    docker_compose       TEXT NOT NULL,
    app_json             TEXT NOT NULL,
    prelaunch            TEXT NOT NULL,
    lite_launcher_dst    TEXT NOT NULL,
    lite_launcher_digest TEXT NOT NULL,
    created_at           INT
);
CREATE TABLE IF NOT EXISTS apps (
    app_id     TEXT PRIMARY KEY,
    app_name   TEXT UNIQUE NOT NULL,
    image_name TEXT NOT NULL,
    usage_text TEXT,
    created_at INT
);
CREATE TABLE IF NOT EXISTS grants (
    user_id    TEXT,
    app_id     TEXT,
    created_at INT,
    PRIMARY KEY(user_id, app_id)
);
CREATE TABLE IF NOT EXISTS licenses (
    id        INTEGER PRIMARY KEY,
    user_id   TEXT,
    app_id    TEXT,
    seq       INT,
    issued_at INT,
    expires_at INT
);
CREATE TABLE IF NOT EXISTS os_images (
    hash TEXT PRIMARY KEY
);
"""


class Store:
    """SQLite store for tenants, ceks, images, the single launcher build, apps,
    grants, the license ledger, and the os-image whitelist."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        self.db_path = db_path or _DB_PATH
        if self.db_path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        # check_same_thread=False so the single connection is usable from FastAPI's
        # threadpool workers; sqlite serializes writes internally.
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    # ─── tenants ──────────────────────────────────────────────────────────────

    def create_tenant(self, user_id: str) -> str:
        """Create a tenant. Returns the plaintext API key (shown once).
        Raises ValueError if the tenant already exists."""
        user_id = (user_id or "").strip()
        if not user_id:
            raise ValueError("user_id required")
        if self.get_tenant(user_id) is not None:
            raise ValueError(f"tenant already exists: {user_id}")
        api_key = generate_api_key()
        self.conn.execute(
            "INSERT INTO tenants(user_id, api_key_hash, created_at) VALUES (?, ?, ?)",
            (user_id, hash_api_key(api_key), int(time.time())),
        )
        self.conn.commit()
        return api_key

    def get_tenant(self, user_id: str) -> Optional[Dict[str, Any]]:
        row = self.conn.execute(
            "SELECT user_id, api_key_hash, created_at FROM tenants WHERE user_id=?",
            (user_id,),
        ).fetchone()
        return dict(row) if row else None

    def find_tenant_by_api_key(self, api_key: str) -> Optional[str]:
        """Resolve a bearer API key to its user_id, or None if no match."""
        if not api_key:
            return None
        for row in self.conn.execute("SELECT user_id, api_key_hash FROM tenants"):
            if row["api_key_hash"] and api_key_matches(api_key, row["api_key_hash"]):
                return row["user_id"]
        return None

    # ─── ceks (EC P-256 content-encryption keypairs) ──────────────────────────
    # Each entry {kid, priv_pem, pub_pem}. Images are encrypted to pub_pem;
    # priv_pem is the CEK, HPKE-sealed to attested launchers, never API-returned.

    def mint_cek(self, kid: str = "") -> dict:
        """Mint a new content-encryption keypair. Persists the private key;
        returns {kid, pub_pem, created_at} — the PRIVATE key is never returned."""
        kid = (kid or "").strip() or secrets.token_hex(8)
        if self.get_cek(kid) is not None:
            raise ValueError(f"kid already exists: {kid}")
        kp = generate_keypair()
        now = int(time.time())
        self.conn.execute(
            "INSERT INTO ceks(kid, priv_pem, pub_pem, created_at) VALUES (?, ?, ?, ?)",
            (kid, kp["priv_pem"], kp["pub_pem"], now),
        )
        self.conn.commit()
        return {"kid": kid, "pub_pem": kp["pub_pem"], "created_at": now}

    def get_cek(self, kid: str) -> Optional[dict]:
        """Return the full cek row (incl. priv_pem) for kid, or None."""
        row = self.conn.execute(
            "SELECT kid, priv_pem, pub_pem, created_at FROM ceks WHERE kid=?", (kid,)
        ).fetchone()
        return dict(row) if row else None

    def list_ceks(self) -> List[dict]:
        """List ceks (kid + public key only; private keys never echoed)."""
        return [
            {"kid": r["kid"], "pub_pem": r["pub_pem"], "created_at": r["created_at"] or 0}
            for r in self.conn.execute(
                "SELECT kid, pub_pem, created_at FROM ceks ORDER BY created_at"
            )
        ]

    # ─── images (per-image registered versions) ───────────────────────────────

    def add_image_version(self, image_name: str, dst_ref: str, digest: str, kid: str) -> dict:
        """Register an (image_name, dst_ref, digest, kid) version. Raises
        ValueError on unknown kid or a duplicate (image_name, digest)."""
        image_name = (image_name or "").strip()
        digest = (digest or "").strip()
        if not image_name or not digest:
            raise ValueError("image_name and digest required")
        if self.get_cek(kid) is None:
            raise ValueError(f"unknown kid: {kid}")
        if self.find_image_by_digest(image_name, digest) is not None:
            raise ValueError(f"image version already exists: {image_name}@{digest}")
        now = int(time.time())
        self.conn.execute(
            "INSERT INTO images(image_name, dst_ref, digest, kid, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (image_name, dst_ref, digest, kid, now),
        )
        self.conn.commit()
        return {"image_name": image_name, "dst_ref": dst_ref, "digest": digest,
                "kid": kid, "created_at": now}

    def get_image_versions(self, image_name: str) -> List[dict]:
        """All registered versions for image_name, newest first."""
        return [
            dict(r)
            for r in self.conn.execute(
                "SELECT image_name, dst_ref, digest, kid, created_at FROM images "
                "WHERE image_name=? ORDER BY created_at DESC, id DESC",
                (image_name,),
            )
        ]

    def get_image_latest(self, image_name: str) -> Optional[dict]:
        """Latest (max created_at) registered version for image_name, or None."""
        row = self.conn.execute(
            "SELECT image_name, dst_ref, digest, kid, created_at FROM images "
            "WHERE image_name=? ORDER BY created_at DESC, id DESC LIMIT 1",
            (image_name,),
        ).fetchone()
        return dict(row) if row else None

    def find_image_by_digest(self, image_name: str, digest: str) -> Optional[dict]:
        """Return the version row for (image_name, digest) if registered, else
        None (fail-closed: registry-agnostic — gated by digest, not by ref)."""
        row = self.conn.execute(
            "SELECT image_name, dst_ref, digest, kid, created_at FROM images "
            "WHERE image_name=? AND digest=?",
            (image_name, digest),
        ).fetchone()
        return dict(row) if row else None

    # ─── launcher (the single trusted build, id=1) ────────────────────────────

    def set_launcher(self, compose_hash: str, app_compose_json: str, docker_compose: str,
                     app_json: str, prelaunch: str, lite_launcher_dst: str,
                     lite_launcher_digest: str) -> dict:
        """Store/replace the single launcher row (id=1). Its compose_hash is the
        G6 whitelist (registering a new launcher replaces the old build)."""
        now = int(time.time())
        self.conn.execute("DELETE FROM launcher WHERE id=1")
        self.conn.execute(
            "INSERT INTO launcher(id, compose_hash, app_compose_json, docker_compose, "
            "app_json, prelaunch, lite_launcher_dst, lite_launcher_digest, created_at) "
            "VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)",
            (compose_hash, app_compose_json, docker_compose, app_json, prelaunch,
             lite_launcher_dst, lite_launcher_digest, now),
        )
        self.conn.commit()
        return self.get_launcher()

    def get_launcher(self) -> Optional[dict]:
        """Return the single launcher row, or None if none registered yet."""
        row = self.conn.execute(
            "SELECT compose_hash, app_compose_json, docker_compose, app_json, "
            "prelaunch, lite_launcher_dst, lite_launcher_digest, created_at "
            "FROM launcher WHERE id=1"
        ).fetchone()
        return dict(row) if row else None

    # ─── apps (authority-assigned random 40-hex app_id) ───────────────────────

    def create_app(self, app_name: str, image_name: str, usage_text: str = "") -> str:
        """Register an app: assign a random 40-hex app_id, bind it to an
        image_name + usage_text. Returns the app_id. Raises ValueError on a
        duplicate app_name."""
        app_name = (app_name or "").strip()
        image_name = (image_name or "").strip()
        if not app_name or not image_name:
            raise ValueError("app_name and image_name required")
        if self.get_app_by_name(app_name) is not None:
            raise ValueError(f"app already exists: {app_name}")
        app_id = secrets.token_hex(20)   # 40 hex chars
        self.conn.execute(
            "INSERT INTO apps(app_id, app_name, image_name, usage_text, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (app_id, app_name, image_name, usage_text or "", int(time.time())),
        )
        self.conn.commit()
        return app_id

    def get_app_by_id(self, app_id: str) -> Optional[dict]:
        row = self.conn.execute(
            "SELECT app_id, app_name, image_name, usage_text, created_at FROM apps "
            "WHERE app_id=?",
            ((app_id or "").lower(),),
        ).fetchone()
        return dict(row) if row else None

    def get_app_by_name(self, app_name: str) -> Optional[dict]:
        row = self.conn.execute(
            "SELECT app_id, app_name, image_name, usage_text, created_at FROM apps "
            "WHERE app_name=?",
            (app_name,),
        ).fetchone()
        return dict(row) if row else None

    def get_app(self, app_id_or_name: str) -> Optional[dict]:
        """Resolve an app by app_id first, falling back to app_name."""
        return (self.get_app_by_id(app_id_or_name)
                or self.get_app_by_name(app_id_or_name))

    def list_apps(self) -> List[dict]:
        """List all apps (app_id + app_name + image_name)."""
        return [
            {"app_id": r["app_id"], "app_name": r["app_name"], "image_name": r["image_name"]}
            for r in self.conn.execute(
                "SELECT app_id, app_name, image_name FROM apps ORDER BY created_at"
            )
        ]

    # ─── grants (tenant → app authorizations) ─────────────────────────────────

    def grant(self, user_id: str, app_id: str) -> None:
        """Authorize tenant user_id for app_id. Raises ValueError on unknown
        tenant/app. Idempotent (INSERT OR IGNORE)."""
        if self.get_tenant(user_id) is None:
            raise ValueError(f"unknown tenant: {user_id}")
        if self.get_app_by_id(app_id) is None:
            raise ValueError(f"unknown app: {app_id}")
        self.conn.execute(
            "INSERT OR IGNORE INTO grants(user_id, app_id, created_at) VALUES (?, ?, ?)",
            (user_id, (app_id or "").lower(), int(time.time())),
        )
        self.conn.commit()

    def is_granted(self, user_id: str, app_id: str) -> bool:
        """True iff tenant user_id is granted app_id (fail-closed)."""
        row = self.conn.execute(
            "SELECT 1 FROM grants WHERE user_id=? AND app_id=?",
            (user_id, (app_id or "").lower()),
        ).fetchone()
        return row is not None

    # ─── license ledger ───────────────────────────────────────────────────────

    def bump_license_seq(self, user_id: str, app_id: str) -> int:
        """Monotonically allocate and record the next license seq for
        (user_id, app_id): max(seq)+1 from the licenses ledger."""
        app_id = (app_id or "").lower()
        row = self.conn.execute(
            "SELECT MAX(seq) AS m FROM licenses WHERE user_id=? AND app_id=?",
            (user_id, app_id),
        ).fetchone()
        seq = (row["m"] or 0) + 1
        self.conn.execute(
            "INSERT INTO licenses(user_id, app_id, seq, issued_at, expires_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (user_id, app_id, seq, int(time.time()), 0),
        )
        self.conn.commit()
        return seq

    def record_license_expiry(self, user_id: str, app_id: str, seq: int, expires_at: int) -> None:
        """Backfill the expires_at of the just-allocated ledger row (audit)."""
        self.conn.execute(
            "UPDATE licenses SET expires_at=? WHERE user_id=? AND app_id=? AND seq=?",
            (expires_at, user_id, (app_id or "").lower(), seq),
        )
        self.conn.commit()

    # ─── os-image whitelist (G4) ──────────────────────────────────────────────

    def add_os_image(self, h: str) -> list:
        h = (h or "").strip().lower()
        if not h:
            raise ValueError("empty hash")
        self.conn.execute("INSERT OR IGNORE INTO os_images(hash) VALUES (?)", (h,))
        self.conn.commit()
        return self.get_os_images()

    def get_os_images(self) -> list:
        return [r["hash"] for r in self.conn.execute(
            "SELECT hash FROM os_images ORDER BY hash"
        )]

    def remove_os_image(self, h: str) -> bool:
        h = (h or "").strip().lower()
        cur = self.conn.execute("DELETE FROM os_images WHERE hash=?", (h,))
        self.conn.commit()
        return cur.rowcount > 0
