// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use cc_eventlog::TdxEventLog;
use thiserror::Error;

use crate::TdxReportData;

type Result<T> = std::result::Result<T, TdxAttestError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TdxAttestError {
    #[error("not supported")]
    NotSupported,
}

pub fn extend_rtmr(_index: u32, _event_type: u32, _digest: [u8; 48]) -> Result<()> {
    Err(TdxAttestError::NotSupported)
}

pub fn log_rtmr_event(_log: &TdxEventLog) -> Result<()> {
    Err(TdxAttestError::NotSupported)
}

pub fn get_quote(_report_data: &TdxReportData) -> Result<Vec<u8>> {
    Err(TdxAttestError::NotSupported)
}
