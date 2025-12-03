// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
pub use linux::*;
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
mod linux;

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
pub use dummy::*;

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
mod dummy;

pub use cc_eventlog as eventlog;

pub type Result<T> = std::result::Result<T, TdxAttestError>;

pub type TdxReportData = [u8; 64];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TdxReport(pub [u8; 1024]);

pub fn extend_rtmr3(event: &str, payload: &[u8]) -> anyhow::Result<()> {
    use anyhow::Context;
    let event_type = eventlog::DSTACK_RUNTIME_EVENT_TYPE;
    let index = 3;
    let log =
        eventlog::TdxEventLogEntry::new(index, event_type, event.to_string(), payload.to_vec());
    let digest = log
        .digest()
        .try_into()
        .ok()
        .context("Invalid digest size")?;
    extend_rtmr(index, event_type, digest).context("Failed to extend RTMR")?;
    log_rtmr_event(&log).context("Failed to log RTMR event")
}
