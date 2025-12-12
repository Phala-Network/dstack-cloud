// SPDX-FileCopyrightText: © 2024 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use crate::codecs::VecOf;
use anyhow::{Context, Result};
use scale::Decode;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use tcg::{TcgDigest, TcgEfiSpecIdEvent};

mod codecs;
mod tcg;
pub mod tpm;

/// The path to the userspace TDX event log file.
pub const RUNTIME_EVENT_LOG_FILE: &str = "/run/log/tdx_mr3/tdx_events.log";
/// The path to boottime ccel file.
const CCEL_FILE: &str = "/sys/firmware/acpi/tables/data/CCEL";
/// The event type for dstack runtime events.
/// This code is not defined in the TCG specification.
/// See https://trustedcomputinggroup.org/wp-content/uploads/PC-ClientSpecific_Platform_Profile_for_TPM_2p0_Systems_v51.pdf
pub const DSTACK_RUNTIME_EVENT_TYPE: u32 = 0x08000001;

/// This is the common struct for tcg event logs to be delivered in different formats.
/// Currently TCG supports several event log formats defined in TCG_PCClient Spec,
/// Canonical Eventlog Spec, etc.
/// This struct provides the functionality to convey event logs in different format
/// according to request.
#[derive(Clone, scale::Decode)]
pub struct TcgEventLog {
    /// IMR index starts from 1
    pub imr_index: u32,
    /// Event type
    pub event_type: u32,
    /// List of digests
    pub digests: VecOf<u32, TcgDigest>,
    /// Raw event data
    pub event: VecOf<u32, u8>,
}

/// This is the TDX event log format that is used to store the event log in the TDX guest.
/// It is a simplified version of the TCG event log format, containing only a single digest
/// and the raw event data. The IMR index is zero-based, unlike the TCG event log format
/// which is one-based.
///
/// As for RTMR3, the digest extended is calculated as `sha384(event_type.to_ne_bytes() || b":" || event || b":" || event_payload)`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TdxEventLogEntry {
    /// IMR index, starts from 0
    pub imr: u32,
    /// Event type
    pub event_type: u32,
    /// Digest
    #[serde(with = "serde_human_bytes", default)]
    digest: Vec<u8>,
    /// Event name
    pub event: String,
    /// Event payload
    #[serde(with = "serde_human_bytes")]
    pub event_payload: Vec<u8>,
}

fn event_digest(ty: u32, event: &str, payload: &[u8]) -> [u8; 48] {
    use sha2::Digest;
    let mut hasher = sha2::Sha384::new();
    hasher.update(ty.to_ne_bytes());
    hasher.update(b":");
    hasher.update(event.as_bytes());
    hasher.update(b":");
    hasher.update(payload);
    hasher.finalize().into()
}

impl TdxEventLogEntry {
    pub fn new(imr: u32, event_type: u32, event: String, event_payload: Vec<u8>) -> Self {
        Self {
            imr,
            event_type,
            digest: vec![],
            event,
            event_payload,
        }
    }

    /// Create a version of this event with payload stripped (for size reduction).
    /// Only call this on events where can_strip_payload() returns true.
    pub fn stripped(&self) -> Self {
        if self.is_dstack_runtime_event() {
            Self {
                imr: self.imr,
                event_type: self.event_type,
                digest: Vec::new(),
                event: self.event.clone(),
                event_payload: self.event_payload.clone(),
            }
        } else {
            Self {
                imr: self.imr,
                event_type: self.event_type,
                digest: self.digest.clone(),
                event: self.event.clone(),
                event_payload: Vec::new(),
            }
        }
    }

    pub fn digest(&self) -> Vec<u8> {
        if self.is_dstack_runtime_event() {
            return event_digest(self.event_type, &self.event, &self.event_payload).to_vec();
        }
        self.digest.clone()
    }

    pub fn is_dstack_runtime_event(&self) -> bool {
        self.event_type == DSTACK_RUNTIME_EVENT_TYPE
    }
}

/// Strip large payloads from event logs to reduce size.
/// CCEL boot-time events only need their digest for RTMR replay, not the payload.
/// Runtime events need their payload for verification, so those are kept.
pub fn strip_event_log_payloads(events: &[TdxEventLogEntry]) -> Vec<TdxEventLogEntry> {
    events.iter().map(|e| e.stripped()).collect()
}

impl TryFrom<TcgEventLog> for TdxEventLogEntry {
    type Error = anyhow::Error;

    fn try_from(value: TcgEventLog) -> Result<Self> {
        if value.digests.len() != 1 {
            return Err(anyhow::anyhow!(
                "expected 1 digest, got {}",
                value.digests.len()
            ));
        }
        let digest = value
            .digests
            .into_inner()
            .into_iter()
            .next()
            .context("digest not found")?
            .hash;
        Ok(TdxEventLogEntry {
            imr: value
                .imr_index
                .checked_sub(1)
                .context("invalid IMR index: must be >= 1")?,
            event_type: value.event_type,
            digest,
            event: Default::default(),
            event_payload: value.event.into(),
        })
    }
}

impl core::fmt::Debug for TcgEventLog {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TcgEventLog")
            .field("imr_index", &self.imr_index)
            .field("event_type", &self.event_type)
            .field(
                "digests",
                &self
                    .digests
                    .iter()
                    .map(|d| hex::encode(&d.hash))
                    .collect::<Vec<_>>(),
            )
            .field("event", &hex::encode(&self.event))
            .finish()
    }
}

const fn alg_id_to_digest_size(alg_id: u16) -> Option<u8> {
    use tcg::*;
    match alg_id {
        TPM_ALG_SHA1 => Some(20),
        TPM_ALG_SHA256 => Some(32),
        TPM_ALG_SHA384 => Some(48),
        TPM_ALG_SHA512 => Some(64),
        _ => None,
    }
}

#[derive(Clone, Debug)]
pub struct EventLogs {
    pub spec_id_header_event: TcgEfiSpecIdEvent,
    pub event_logs: Vec<TcgEventLog>,
}

impl scale::Decode for TcgDigest {
    fn decode<I: scale::Input>(input: &mut I) -> Result<Self, scale::Error> {
        let algo_id = u16::decode(input)?;
        let digest_size =
            alg_id_to_digest_size(algo_id).ok_or(scale::Error::from("Unsupported algorithm ID"))?;
        let mut digest_data = vec![0; digest_size as usize];
        input
            .read(&mut digest_data)
            .map_err(|_| scale::Error::from("failed to read digest_data"))?;
        Ok(TcgDigest {
            algo_id,
            hash: digest_data,
        })
    }
}

impl EventLogs {
    pub fn decode(input: &mut &[u8]) -> Result<Self> {
        let (_spec_id_header, spec_id_header_event) =
            parse_spec_id_event_log(input).context("Failed to parse spec id event")?;
        let mut event_logs = vec![];
        loop {
            // A tmp head_buffer is used to peek the imr and event type
            let head_buffer = &mut &input[..];
            let imr = u32::decode(head_buffer).context("failed to decode imr")?;
            if imr == 0xFFFFFFFF {
                break;
            }
            let event_log = TcgEventLog::decode(input).context("Failed to parse event log")?;
            event_logs.push(event_log);
        }
        Ok(EventLogs {
            spec_id_header_event,
            event_logs,
        })
    }

    pub fn decode_from_ccel_file() -> Result<Self> {
        let data = fs_err::read(CCEL_FILE).context("Failed to read CCEL")?;
        Self::decode(&mut data.as_slice())
    }

    pub fn to_tdx_event_logs(&self) -> Result<Vec<TdxEventLogEntry>> {
        self.event_logs
            .iter()
            .filter(|log| log.imr_index > 0) // GCP fills some IMRs starting from 0
            .cloned()
            .map(TdxEventLogEntry::try_from)
            .collect()
    }
}

fn parse_spec_id_event_log<I: scale::Input>(
    input: &mut I,
) -> Result<(TcgEventLog, TcgEfiSpecIdEvent)> {
    #[derive(Decode)]
    struct Header {
        imr_index: u32,
        header_event_type: u32,
        digest_hash: [u8; 20],
        header_event: VecOf<u32, u8>,
    }

    let decoded_header = Header::decode(input).context("failed to decode log_item")?;
    // Parse EFI Spec Id Event structure
    let input = &mut decoded_header.header_event.as_slice();
    let spec_id_event =
        TcgEfiSpecIdEvent::decode(input).context("failed to decode TcgEfiSpecIdEvent")?;

    let digests = vec![TcgDigest {
        algo_id: tcg::TPM_ALG_ERROR,
        hash: decoded_header.digest_hash.to_vec(),
    }];
    let spec_id_header = TcgEventLog {
        imr_index: decoded_header.imr_index,
        event_type: decoded_header.header_event_type,
        digests: (digests.len() as u32, digests).into(),
        event: decoded_header.header_event,
    };
    Ok((spec_id_header, spec_id_event))
}

/// Read runtime event logs from the runtime event log file
pub fn read_runtime_event_logs() -> Result<Vec<TdxEventLogEntry>> {
    let data = match fs_err::read_to_string(RUNTIME_EVENT_LOG_FILE) {
        Ok(data) => data,
        Err(e) => {
            if e.kind() == std::io::ErrorKind::NotFound {
                return Ok(vec![]);
            }
            return Err(e).context("Failed to read user event log");
        }
    };
    let mut event_logs = vec![];
    for line in data.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let event_log = serde_json::from_str::<TdxEventLogEntry>(line)
            .context("Failed to decode user event log")?;
        event_logs.push(event_log);
    }
    Ok(event_logs)
}

/// Read both boottime and runtime event logs.
pub fn read_event_logs() -> Result<Vec<TdxEventLogEntry>> {
    let mut event_logs = EventLogs::decode_from_ccel_file()?.to_tdx_event_logs()?;
    event_logs.extend(read_runtime_event_logs()?);
    Ok(event_logs)
}

/// Replay event logs
pub fn replay_event_logs(
    eventlog: &[TdxEventLogEntry],
    to_event: Option<&str>,
    imr: u32,
) -> Result<[u8; 48]> {
    let mut mr = [0u8; 48];

    for event in eventlog.iter() {
        if event.imr == imr {
            let mut hasher = sha2::Sha384::new();
            hasher.update(mr);
            hasher.update(event.digest());
            mr = hasher.finalize().into();
        }
        if let Some(to_event) = to_event {
            if event.event == to_event {
                break;
            }
        }
    }

    Ok(mr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ccel() {
        let boot_time_data = include_bytes!("../samples/ccel.bin");
        let event_logs = EventLogs::decode(&mut boot_time_data.as_slice()).unwrap();
        insta::assert_debug_snapshot!(&event_logs.event_logs);
        let tdx_event_logs = event_logs.to_tdx_event_logs().unwrap();
        let json = serde_json::to_string_pretty(&tdx_event_logs).unwrap();
        insta::assert_snapshot!(json);
    }
}
