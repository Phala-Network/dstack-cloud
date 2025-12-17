// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Attestation functions

use std::{borrow::Cow, str::FromStr};

use anyhow::{anyhow, bail, Context, Result};
use dcap_qvl::{
    quote::{EnclaveReport, Quote, Report, TDReport10, TDReport15},
    verify::VerifiedReport as TdxVerifiedReport,
};
use dstack_types::Platform;
use scale::{Decode, Encode};
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use tpm_qvl::verify::VerifiedReport as TpmVerifiedReport;
use x509_parser::parse_x509_certificate;

use crate::{oids, traits::CertExt};
use cc_eventlog::TdxEventLogEntry as EventLog;
use or_panic::ResultOrPanic;
use serde_human_bytes as hex_bytes;

// Re-export TpmQuote from tpm-types
pub use tpm_types::TpmQuote;

/// Attestation mode
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub enum AttestationMode {
    /// Intel TDX with DCAP quote only
    #[serde(rename = "dstack-tdx")]
    #[default]
    DstackTdx,
    /// GCP TDX with DCAP quote only
    #[serde(rename = "gcp-tdx")]
    GcpTdx,
    /// Dstack attestation SDK in AWS Nitro Enclave
    #[serde(rename = "dstack-nitro")]
    DstackNitro,
}

impl FromStr for AttestationMode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "dstack-tdx" => Ok(Self::DstackTdx),
            "gcp-tdx" => Ok(Self::GcpTdx),
            "dstack-nitro" => Ok(Self::DstackNitro),
            _ => bail!("Invalid attestation mode: {s}"),
        }
    }
}

impl AttestationMode {
    /// Get string representation
    pub fn as_str(&self) -> &str {
        match self {
            Self::DstackTdx => "dstack-tdx",
            Self::GcpTdx => "gcp-tdx",
            Self::DstackNitro => "dstack-nitro",
        }
    }

    /// Detect attestation mode from system
    pub fn detect() -> Result<Self> {
        // Fallback: detect from available devices
        let has_tdx = std::path::Path::new("/dev/tdx_guest").exists();

        // First, try to detect platform from DMI board name
        let platform = Platform::detect().context("Failed to detect platform")?;
        match platform {
            Platform::Dstack => {
                if has_tdx {
                    return Ok(Self::DstackTdx);
                }
                bail!("Unsupported platform: Dstack");
            }
            Platform::Gcp => {
                // GCP platform: TDX + TPM dual mode
                if has_tdx {
                    return Ok(Self::GcpTdx);
                }
                bail!("Unsupported platform: GCP");
            }
        }
    }

    /// Check if TDX quote should be included
    pub fn has_tdx(&self) -> bool {
        match self {
            Self::DstackTdx => true,
            Self::GcpTdx => true,
            Self::DstackNitro => false,
        }
    }

    /// Check if TPM quote should be included
    pub fn has_tpm(&self) -> bool {
        match self {
            Self::DstackTdx => false,
            Self::GcpTdx => true,
            Self::DstackNitro => true,
        }
    }
}

/// The content type of a quote. A CVM should only generate quotes for these types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuoteContentType<'a> {
    /// The public key of KMS root CA
    KmsRootCa,
    /// The public key of the RA-TLS certificate
    RaTlsCert,
    /// App defined data
    AppData,
    /// The custom content type
    Custom(&'a str),
}

/// The default hash algorithm used to hash the report data.
pub const DEFAULT_HASH_ALGORITHM: &str = "sha512";

impl QuoteContentType<'_> {
    /// The tag of the content type used in the report data.
    pub fn tag(&self) -> &str {
        match self {
            Self::KmsRootCa => "kms-root-ca",
            Self::RaTlsCert => "ratls-cert",
            Self::AppData => "app-data",
            Self::Custom(tag) => tag,
        }
    }

    /// Convert the content to the report data.
    pub fn to_report_data(&self, content: &[u8]) -> [u8; 64] {
        self.to_report_data_with_hash(content, "")
            .or_panic("sha512 hash should not fail")
    }

    /// Convert the content to the report data with a specific hash algorithm.
    pub fn to_report_data_with_hash(&self, content: &[u8], hash: &str) -> Result<[u8; 64]> {
        macro_rules! do_hash {
            ($hash: ty) => {{
                // The format is:
                // hash(<tag>:<content>)
                let mut hasher = <$hash>::new();
                hasher.update(self.tag().as_bytes());
                hasher.update(b":");
                hasher.update(content);
                let output = hasher.finalize();

                let mut padded = [0u8; 64];
                padded[..output.len()].copy_from_slice(&output);
                padded
            }};
        }
        let hash = if hash.is_empty() {
            DEFAULT_HASH_ALGORITHM
        } else {
            hash
        };
        let output = match hash {
            "sha256" => do_hash!(sha2::Sha256),
            "sha384" => do_hash!(sha2::Sha384),
            "sha512" => do_hash!(sha2::Sha512),
            "sha3-256" => do_hash!(sha3::Sha3_256),
            "sha3-384" => do_hash!(sha3::Sha3_384),
            "sha3-512" => do_hash!(sha3::Sha3_512),
            "keccak256" => do_hash!(sha3::Keccak256),
            "keccak384" => do_hash!(sha3::Keccak384),
            "keccak512" => do_hash!(sha3::Keccak512),
            "raw" => content.try_into().ok().context("invalid content length")?,
            _ => bail!("invalid hash algorithm"),
        };
        Ok(output)
    }
}

/// Represents a verified attestation
#[derive(Clone)]
pub struct DstackVerifiedReport {
    /// The verified TDX report
    pub tdx_report: Option<TdxVerifiedReport>,
    /// The verified TPM report
    pub tpm_report: Option<TpmVerifiedReport>,
}

fn get_report_data(report: &TdxVerifiedReport) -> [u8; 64] {
    match report.report {
        Report::SgxEnclave(enclave_report) => enclave_report.report_data,
        Report::TD10(tdreport10) => tdreport10.report_data,
        Report::TD15(tdreport15) => tdreport15.base.report_data,
    }
}

impl DstackVerifiedReport {
    /// Check if the report is empty
    pub fn is_empty(&self) -> bool {
        self.tdx_report.is_none() && self.tpm_report.is_none()
    }

    /// Ensure report data matches
    pub fn ensure_report_data(&self, report_data: Option<[u8; 64]>) -> Result<[u8; 64]> {
        let expected = match (&self.tdx_report, report_data) {
            (Some(tdx_report), Some(rd)) => {
                let td_report_data = get_report_data(tdx_report);
                if td_report_data != rd {
                    bail!("report data mismatch");
                }
                td_report_data
            }
            (Some(tdx_report), None) => get_report_data(tdx_report),
            (None, Some(rd)) => rd,
            (None, None) => bail!("no verified report"),
        };

        if let Some(tpm_report) = &self.tpm_report {
            if tpm_report.attest.qualified_data != expected {
                bail!("report data mismatch");
            }
        }
        Ok(expected)
    }
}

/// Represents a verified attestation
pub type VerifiedAttestation = Attestation<DstackVerifiedReport>;

/// Represents a TDX quote
#[derive(Clone)]
pub struct TdxQuote {
    /// The quote gererated by Intel QE
    pub quote: Vec<u8>,
    /// The event log
    pub event_log: Vec<EventLog>,
}

/// Attestation data
#[derive(Clone)]
pub struct Attestation<R = ()> {
    /// Attestation mode
    pub mode: AttestationMode,

    /// TDX quote (only for TDX mode)
    pub tdx_quote: Option<TdxQuote>,

    /// TPM quote (only for TPM mode)
    pub tpm_quote: Option<TpmQuote>,

    /// Verified report
    pub report: R,
}

impl<T> Attestation<T> {
    /// Decode the quote
    pub fn decode_tdx_quote(&self) -> Result<Quote> {
        let Some(tdx_quote) = &self.tdx_quote else {
            bail!("tdx_quote not found");
        };
        Quote::parse(&tdx_quote.quote)
    }

    fn find_event(&self, imr: u32, name: &str) -> Result<EventLog> {
        let Some(tdx_quote) = &self.tdx_quote else {
            bail!("tdx_quote not found");
        };
        for event in &tdx_quote.event_log {
            if event.imr == 3 && event.event == "system-ready" {
                break;
            }
            if event.imr == imr && event.event == name {
                return Ok(event.clone());
            }
        }
        Err(anyhow!("event {name} not found"))
    }

    /// Replay event logs
    pub fn replay_rtmr3(&self, to_event: Option<&str>) -> Result<[u8; 48]> {
        let Some(tdx_quote) = &self.tdx_quote else {
            bail!("tdx_quote not found");
        };
        cc_eventlog::replay_event_logs(&tdx_quote.event_log, to_event, 3)
    }

    fn find_event_payload(&self, event: &str) -> Result<Vec<u8>> {
        self.find_event(3, event).map(|event| event.event_payload)
    }

    /// Decode the app-id from the event log
    pub fn decode_app_id(&self) -> Result<String> {
        self.find_event(3, "app-id")
            .map(|event| hex::encode(&event.event_payload))
    }

    /// Decode the instance-id from the event log
    pub fn decode_instance_id(&self) -> Result<String> {
        self.find_event(3, "instance-id")
            .map(|event| hex::encode(&event.event_payload))
    }

    /// Decode the upgraded app-id from the event log
    pub fn decode_compose_hash(&self) -> Result<String> {
        let event = self.find_event(3, "compose-hash").or_else(|_| {
            // Old images use this event name
            self.find_event(3, "upgraded-app-id")
        })?;
        Ok(hex::encode(&event.event_payload))
    }

    /// Decode the app info from the event log
    pub fn decode_app_info(&self, boottime_mr: bool) -> Result<AppInfo> {
        let rtmr3 = self
            .replay_rtmr3(boottime_mr.then_some("boot-mr-done"))
            .context("Failed to replay event logs")?;
        let quote = self.decode_tdx_quote()?;
        let device_id = sha256(&[&quote.header.user_data]).to_vec();
        let td_report = quote.report.as_td10().context("TDX report not found")?;
        let key_provider_info = if boottime_mr {
            vec![]
        } else {
            self.find_event_payload("key-provider").unwrap_or_default()
        };
        let mr_key_provider = if key_provider_info.is_empty() {
            [0u8; 32]
        } else {
            sha256(&[&key_provider_info])
        };
        let mr_system = sha256(&[
            &td_report.mr_td,
            &td_report.rt_mr0,
            &td_report.rt_mr1,
            &td_report.rt_mr2,
            &mr_key_provider,
        ]);
        let mr_aggregated = {
            use sha2::{Digest as _, Sha256};
            let mut hasher = Sha256::new();
            for d in [
                &td_report.mr_td,
                &td_report.rt_mr0,
                &td_report.rt_mr1,
                &td_report.rt_mr2,
                &rtmr3,
            ] {
                hasher.update(d);
            }
            // For backward compatibility. Don't include mr_config_id, mr_owner, mr_owner_config if they are all 0.
            if td_report.mr_config_id != [0u8; 48]
                || td_report.mr_owner != [0u8; 48]
                || td_report.mr_owner_config != [0u8; 48]
            {
                hasher.update(td_report.mr_config_id);
                hasher.update(td_report.mr_owner);
                hasher.update(td_report.mr_owner_config);
            }
            hasher.finalize().into()
        };
        Ok(AppInfo {
            app_id: self.find_event_payload("app-id").unwrap_or_default(),
            compose_hash: self.find_event_payload("compose-hash").unwrap_or_default(),
            instance_id: self.find_event_payload("instance-id").unwrap_or_default(),
            device_id,
            mrtd: td_report.mr_td,
            rtmr0: td_report.rt_mr0,
            rtmr1: td_report.rt_mr1,
            rtmr2: td_report.rt_mr2,
            rtmr3,
            os_image_hash: self.find_event_payload("os-image-hash").unwrap_or_default(),
            mr_system,
            mr_aggregated,
            key_provider_info,
        })
    }

    /// Decode the rootfs hash from the event log
    pub fn decode_rootfs_hash(&self) -> Result<String> {
        self.find_event(3, "rootfs-hash")
            .map(|event| hex::encode(event.digest()))
    }

    /// Decode the report data in the quote
    pub fn decode_tdx_report_data(&self) -> Result<[u8; 64]> {
        match self.decode_tdx_quote()?.report {
            Report::SgxEnclave(report) => Ok(report.report_data),
            Report::TD10(report) => Ok(report.report_data),
            Report::TD15(report) => Ok(report.base.report_data),
        }
    }
}

#[cfg(feature = "quote")]
impl Attestation {
    /// Create an attestation for local machine (auto-detect mode)
    pub fn local() -> Result<Self> {
        let mode = AttestationMode::detect()?;
        let report_data = [0u8; 64];
        let tdx_quote = if mode.has_tdx() {
            let quote = tdx_attest::get_quote(&report_data).context("Failed to get quote")?;
            let event_log =
                tdx_attest::eventlog::read_event_logs().context("Failed to read event logs")?;
            Some(TdxQuote { quote, event_log })
        } else {
            None
        };
        let tpm_quote = if mode.has_tpm() {
            let tpm_ctx = tpm_attest::TpmContext::detect().context("Failed to open TPM context")?;
            let quote = tpm_ctx
                .create_quote(&report_data, &tpm_attest::dstack_pcr_policy())
                .context("Failed to create TPM quote")?;
            Some(quote)
        } else {
            None
        };
        Ok(Self {
            mode,
            tdx_quote,
            tpm_quote,
            report: (),
        })
    }
}

impl Attestation {
    /// Extract attestation data from a certificate
    pub fn from_cert(cert: &impl CertExt) -> Result<Option<Self>> {
        Self::from_ext_getter(|oid| cert.get_extension_bytes(oid))
    }

    /// From an extension getter
    pub fn from_ext_getter(
        get_ext: impl Fn(&[u64]) -> Result<Option<Vec<u8>>>,
    ) -> Result<Option<Self>> {
        // Try to detect attestation mode from certificate extension
        let mode = if let Some(mode_bytes) = get_ext(oids::PHALA_RATLS_ATTESTATION_MODE)? {
            std::str::from_utf8(&mode_bytes)
                .context("Invalid attestation mode encoding")?
                .parse()
                .context("Invalid attestation mode")?
        } else {
            // Backward compatibility: if no mode specified
            let has_tdx = get_ext(oids::PHALA_RATLS_TDX_QUOTE)?.is_some();
            if !has_tdx {
                bail!("Unknown attestation mode");
            }
            AttestationMode::DstackTdx
        };
        let tdx_quote;
        let tdx_event_log: Vec<EventLog>;

        if mode.has_tdx() {
            tdx_quote = match get_ext(oids::PHALA_RATLS_TDX_QUOTE)? {
                Some(v) => v,
                None => return Ok(None),
            };
            let mut raw_event_log =
                get_ext(oids::PHALA_RATLS_EVENT_LOG)?.context("TDX event log missing")?;
            tdx_event_log = if !raw_event_log.is_empty() {
                // Decompress if needed (handles both compressed and uncompressed formats)
                raw_event_log = crate::cert::decompress_event_log(&raw_event_log)
                    .context("failed to decompress event log")?;
                serde_json::from_slice(&raw_event_log).context("invalid event log")?
            } else {
                vec![]
            };
        } else {
            tdx_quote = vec![];
            tdx_event_log = vec![];
        };

        let tpm_quote = if mode.has_tpm() {
            let tpm_quote_json = match get_ext(oids::PHALA_RATLS_TPM_QUOTE)? {
                Some(v) => v,
                None => return Ok(None),
            };
            Some(
                serde_json::from_slice(&tpm_quote_json)
                    .context("Failed to parse TPM quote data")?,
            )
        } else {
            None
        };

        Ok(Some(Self {
            mode,
            tdx_quote: mode.has_tdx().then_some(TdxQuote {
                quote: tdx_quote,
                event_log: tdx_event_log,
            }),
            tpm_quote,
            report: (),
        }))
    }

    /// Extract attestation from x509 certificate
    pub fn from_der(cert: &[u8]) -> Result<Option<Self>> {
        let (_, cert) = parse_x509_certificate(cert).context("Failed to parse certificate")?;
        Self::from_cert(&cert)
    }

    /// Extract attestation from x509 certificate in PEM format
    pub fn from_pem(cert: &[u8]) -> Result<Option<Self>> {
        let (_, pem) =
            x509_parser::pem::parse_x509_pem(cert).context("Failed to parse certificate")?;
        let cert = pem.parse_x509().context("Failed to parse certificate")?;
        Self::from_cert(&cert)
    }

    /// Verify the quote
    pub async fn verify_with_ra_pubkey(
        self,
        ra_pubkey_der: &[u8],
        pccs_url: Option<&str>,
    ) -> Result<VerifiedAttestation> {
        let expected_report_data = QuoteContentType::RaTlsCert.to_report_data(ra_pubkey_der);
        self.verify(Some(expected_report_data), pccs_url).await
    }

    /// Verify the quote
    pub async fn verify(
        self,
        report_data: Option<[u8; 64]>,
        pccs_url: Option<&str>,
    ) -> Result<VerifiedAttestation> {
        let tpm_report = if self.mode.has_tpm() {
            let report = self
                .verify_tpm()
                .await
                .context("Failed to verify TPM quote")?;
            Some(report)
        } else {
            None
        };
        let tdx_report = if self.mode.has_tdx() {
            let report = self.verify_tdx(pccs_url).await?;
            Some(report)
        } else {
            None
        };
        let report = DstackVerifiedReport {
            tdx_report,
            tpm_report,
        };
        if report.is_empty() {
            bail!("nothing verified");
        }
        report.ensure_report_data(report_data)?;
        Ok(VerifiedAttestation {
            mode: self.mode,
            tdx_quote: self.tdx_quote,
            tpm_quote: self.tpm_quote,
            report,
        })
    }

    async fn verify_tpm(&self) -> Result<TpmVerifiedReport> {
        let tpm_quote = self.tpm_quote.as_ref().context("TPM quote missing")?;
        tpm_qvl::get_collateral_and_verify(tpm_quote).await
    }

    async fn verify_tdx(&self, pccs_url: Option<&str>) -> Result<TdxVerifiedReport> {
        let quote = &self.tdx_quote.as_ref().context("TDX quote missing")?.quote;
        let mut pccs_url = Cow::Borrowed(pccs_url.unwrap_or_default());
        if pccs_url.is_empty() {
            // try to read from PCCS_URL env var
            pccs_url = match std::env::var("PCCS_URL") {
                Ok(url) => Cow::Owned(url),
                Err(_) => Cow::Borrowed(""),
            };
        }
        let tdx_report =
            dcap_qvl::collateral::get_collateral_and_verify(quote, Some(pccs_url.as_ref()))
                .await
                .context("Failed to get collateral")?;
        let report = tdx_report.report.as_td10().context("TD10 report missing")?;
        // Replay the event logs
        let rtmr3 = self
            .replay_rtmr3(None)
            .context("Failed to replay event logs")?;
        if rtmr3 != report.rt_mr3 {
            bail!(
                "RTMR3 mismatch, quoted: {}, replayed: {}",
                hex::encode(report.rt_mr3),
                hex::encode(rtmr3),
            );
        }
        validate_tcb(&tdx_report)?;
        Ok(tdx_report)
    }
}

impl Attestation<DstackVerifiedReport> {}

/// Validate the TCB attributes
pub fn validate_tcb(report: &TdxVerifiedReport) -> Result<()> {
    fn validate_td10(report: &TDReport10) -> Result<()> {
        let is_debug = report.td_attributes[0] & 0x01 != 0;
        if is_debug {
            bail!("Debug mode is not allowed");
        }
        if report.mr_signer_seam != [0u8; 48] {
            bail!("Invalid mr signer seam");
        }
        Ok(())
    }
    fn validate_td15(report: &TDReport15) -> Result<()> {
        if report.mr_service_td != [0u8; 48] {
            bail!("Invalid mr service td");
        }
        validate_td10(&report.base)
    }
    fn validate_sgx(report: &EnclaveReport) -> Result<()> {
        let is_debug = report.attributes[0] & 0x02 != 0;
        if is_debug {
            bail!("Debug mode is not allowed");
        }
        Ok(())
    }
    match &report.report {
        Report::TD15(report) => validate_td15(report),
        Report::TD10(report) => validate_td10(report),
        Report::SgxEnclave(report) => validate_sgx(report),
    }
}

/// Information about the app extracted from event log
#[derive(Debug, Clone, Serialize)]
pub struct AppInfo {
    /// App ID
    #[serde(with = "hex_bytes")]
    pub app_id: Vec<u8>,
    /// SHA256 of the app compose file
    #[serde(with = "hex_bytes")]
    pub compose_hash: Vec<u8>,
    /// ID of the CVM instance
    #[serde(with = "hex_bytes")]
    pub instance_id: Vec<u8>,
    /// ID of the device
    #[serde(with = "hex_bytes")]
    pub device_id: Vec<u8>,
    /// TCB info
    #[serde(with = "hex_bytes")]
    pub mrtd: [u8; 48],
    /// Runtime MR0
    #[serde(with = "hex_bytes")]
    pub rtmr0: [u8; 48],
    /// Runtime MR1
    #[serde(with = "hex_bytes")]
    pub rtmr1: [u8; 48],
    /// Runtime MR2
    #[serde(with = "hex_bytes")]
    pub rtmr2: [u8; 48],
    /// Runtime MR3
    #[serde(with = "hex_bytes")]
    pub rtmr3: [u8; 48],
    /// Measurement of everything except the app info
    #[serde(with = "hex_bytes")]
    pub mr_system: [u8; 32],
    /// Measurement of the entire vm execution environment
    #[serde(with = "hex_bytes")]
    pub mr_aggregated: [u8; 32],
    /// Measurement of the app image
    #[serde(with = "hex_bytes")]
    pub os_image_hash: Vec<u8>,
    /// Key provider info
    #[serde(with = "hex_bytes")]
    pub key_provider_info: Vec<u8>,
}

fn sha256(data: &[&[u8]]) -> [u8; 32] {
    use sha2::{Digest as _, Sha256};
    let mut hasher = Sha256::new();
    for d in data {
        hasher.update(d);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_report_data_with_hash() {
        let content_type = QuoteContentType::AppData;
        let content = b"test content";

        let report_data = content_type.to_report_data(content);
        assert_eq!(hex::encode(report_data), "7ea0b744ed5e9c0c83ff9f575668e1697652cd349f2027cdf26f918d4c53e8cd50b5ea9b449b4c3d50e20ae00ec29688d5a214e8daff8a10041f5d624dae8a01");

        // Test SHA-256
        let result = content_type
            .to_report_data_with_hash(content, "sha256")
            .unwrap();
        assert_eq!(result[32..], [0u8; 32]); // Check padding
        assert_ne!(result[..32], [0u8; 32]); // Check hash is non-zero

        // Test SHA-384
        let result = content_type
            .to_report_data_with_hash(content, "sha384")
            .unwrap();
        assert_eq!(result[48..], [0u8; 16]); // Check padding
        assert_ne!(result[..48], [0u8; 48]); // Check hash is non-zero

        // Test default
        let result = content_type.to_report_data_with_hash(content, "").unwrap();
        assert_ne!(result, [0u8; 64]); // Should fill entire buffer

        // Test raw content
        let exact_content = [42u8; 64];
        let result = content_type
            .to_report_data_with_hash(&exact_content, "raw")
            .unwrap();
        assert_eq!(result, exact_content);

        // Test invalid raw content length
        let invalid_content = [42u8; 65];
        assert!(content_type
            .to_report_data_with_hash(&invalid_content, "raw")
            .is_err());

        // Test invalid hash algorithm
        assert!(content_type
            .to_report_data_with_hash(content, "invalid")
            .is_err());
    }
}
