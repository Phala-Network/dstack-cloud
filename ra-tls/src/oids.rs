// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! OIDs used by the RATLS protocol.

/// OID for the TDX quote extension.
pub const PHALA_RATLS_TDX_QUOTE: &[u64] = &[1, 3, 6, 1, 4, 1, 62397, 1, 1];
/// OID for the TDX event log extension.
pub const PHALA_RATLS_EVENT_LOG: &[u64] = &[1, 3, 6, 1, 4, 1, 62397, 1, 2];
/// OID for the TDX app ID extension.
pub const PHALA_RATLS_APP_ID: &[u64] = &[1, 3, 6, 1, 4, 1, 62397, 1, 3];
/// OID for Special Certificate Usage.
pub const PHALA_RATLS_CERT_USAGE: &[u64] = &[1, 3, 6, 1, 4, 1, 62397, 1, 4];
/// OID for attestation mode (vTPM or TDX).
pub const PHALA_RATLS_ATTESTATION_MODE: &[u64] = &[1, 3, 6, 1, 4, 1, 62397, 1, 5];
/// OID for TPM Quote (vTPM mode).
pub const PHALA_RATLS_TPM_QUOTE: &[u64] = &[1, 3, 6, 1, 4, 1, 62397, 1, 6];
/// OID for TPM Event Log (vTPM mode, optional).
pub const PHALA_RATLS_TPM_EVENT_LOG: &[u64] = &[1, 3, 6, 1, 4, 1, 62397, 1, 7];
