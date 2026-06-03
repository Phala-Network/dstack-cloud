# vendor-platform

Minimal vendor authorization platform for the dstack GCP private deployment
(air-gapped courier protocol).  Implements the three endpoints the `dstack-cloud kms`
CLI commands call during KMS provisioning and AuthBundle renewal.

## Quick start

```bash
cd vendor-platform
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8080 --reload
```

The API is then available at `http://localhost:8080`.

## Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET  | `/api/v1/platform-pubkey` | Return the platform Ed25519 public key |
| POST | `/api/v1/challenge`       | Issue a single-use nonce |
| POST | `/api/v1/provision`       | Verify quote, return sealed root + AuthBundle |
| POST | `/api/v1/sync-auth`       | Renew AuthBundle without re-provisioning root |

Interactive API docs: `http://localhost:8080/docs`

## P0 limitations (see TODO comments in source)

- TDX quote verification is skipped — every quote is trusted.
- Root key is shipped as plaintext base64 instead of HPKE-encrypted to the
  transport X25519 key from the KMS sidecar.
- Platform signing key is ephemeral (regenerated on each restart); use an
  HSM-backed key in production.
- Customer state is stored in `~/.config/vendor-platform/customers.json`;
  replace with a proper database in production.
