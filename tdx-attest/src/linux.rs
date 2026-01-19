// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: BUSL-1.1

use anyhow::bail;
use std::path::PathBuf;

use fs_err as fs;
use thiserror::Error;

use crate::Result;
use crate::TdxReportData;

mod configfs;

/// TSM measurements sysfs paths for RTMR extend (kernel 6.17+)
const TSM_MEASUREMENTS_PATH: &str = "/sys/class/misc/tdx_guest/measurements";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TdxAttestError {
    #[error("unexpected error")]
    Unexpected,
    #[error("invalid parameter")]
    InvalidParameter,
    #[error("out of memory")]
    OutOfMemory,
    #[error("not supported")]
    NotSupported,
    #[error("quote generation failed")]
    QuoteFailure,
    #[error("busy")]
    Busy,
    #[error("device failure")]
    DeviceFailure,
}

/// Get TDX quote using configfs interface
///
/// This uses the kernel's TSM (Trusted Security Module) configfs interface
/// at `/sys/kernel/config/tsm/report/` to generate attestation quotes.
pub fn get_quote(report_data: &TdxReportData) -> Result<Vec<u8>> {
    configfs::get_quote(report_data).map_err(|e| {
        log::error!("failed to get quote via configfs: {}", e);
        TdxAttestError::QuoteFailure
    })
}

/// Find the TSM measurements sysfs directory
fn find_tsm_measurements_dir() -> Option<PathBuf> {
    let path = PathBuf::from(TSM_MEASUREMENTS_PATH);
    if !path.exists() {
        return None;
    }
    Some(path)
}

/// Extend RTMR using TSM measurements sysfs interface (kernel 6.17+)
fn extend_rtmr_tsm(index: u32, digest: &[u8; 48]) -> anyhow::Result<()> {
    let Some(measurements_dir) = find_tsm_measurements_dir() else {
        bail!("TSM measurements sysfs not found")
    };

    let rtmr_file = measurements_dir.join(format!("rtmr{}:sha384", index));

    if !rtmr_file.exists() {
        bail!("RTMR{} sysfs file not found: {:?}", index, rtmr_file);
    }

    fs::write(&rtmr_file, digest)?;
    Ok(())
}

/// Extend RTMR with automatic fallback
///
/// Uses TSM measurements sysfs (kernel 6.17+)
pub fn extend_rtmr(index: u32, _event_type: u32, digest: [u8; 48]) -> Result<()> {
    extend_rtmr_tsm(index, &digest).map_err(|e| {
        log::error!("failed to extend RTMR{}: {}", index, e);
        TdxAttestError::NotSupported
    })
}
