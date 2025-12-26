// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub use linux::*;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux;

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
pub use dummy::*;

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
mod dummy;

pub use cc_eventlog as eventlog;

pub type Result<T> = std::result::Result<T, TdxAttestError>;

pub type TdxReportData = [u8; 64];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TdxReport(pub [u8; 1024]);
