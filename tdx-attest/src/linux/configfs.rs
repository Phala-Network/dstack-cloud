// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Pure Rust implementation of TDX quote generation using Linux TSM configfs interface
//!
//! This module provides a native Rust implementation that directly uses the kernel's
//! TSM (Trusted Security Module) configfs interface at `/sys/kernel/config/tsm/report/`.

use std::io::Read;
use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use fs_err as fs;

use crate::TdxReportData;

const CONFIGFS_PATH: &str = "/sys/kernel/config/tsm/report/com.intel.dcap";
const QUOTE_BUF_SIZE: usize = 8 * 1024; // 8KB
const QUOTE_MIN_SIZE: usize = 1020;
const MAX_RETRIES: usize = 3;
const RETRY_DELAY: Duration = Duration::from_millis(100);

/// Read generation counter from configfs
fn read_generation() -> Result<u64> {
    let generation_str = fs::read_to_string(format!("{CONFIGFS_PATH}/generation"))
        .context("failed to read generation")?;
    let generation = generation_str
        .trim()
        .parse::<u64>()
        .context("failed to parse generation")?;
    Ok(generation)
}

/// Get TDX quote via configfs interface
///
/// This function uses generation counters to detect concurrent access:
/// 1. Read generation counter (gen1)
/// 2. Write report_data to inblob
/// 3. Wait for generation to increment (gen2 = gen1 + 1)
/// 4. Read quote from outblob
/// 5. Verify generation hasn't changed (gen3 = gen2)
pub fn get_quote(report_data: &TdxReportData) -> Result<Vec<u8>> {
    // Verify configfs exists
    if !Path::new(CONFIGFS_PATH).exists() {
        bail!("TSM configfs not found at {CONFIGFS_PATH}. Is TSM_REPORT enabled in kernel?");
    }

    // Read initial generation
    let gen1 = read_generation().context("failed to read generation (1)")?;

    // Write report_data to inblob with retry on EBUSY
    let mut last_err = None;
    for retry in 0..MAX_RETRIES {
        match fs::write(format!("{CONFIGFS_PATH}/inblob"), report_data) {
            Ok(_) => {
                last_err = None;
                break;
            }
            Err(e) => {
                last_err = Some(e);
                if retry < MAX_RETRIES - 1 {
                    std::thread::sleep(RETRY_DELAY);
                }
            }
        }
    }

    if let Some(err) = last_err {
        bail!("failed to write inblob after {MAX_RETRIES} retries: {err}");
    }

    // Wait for generation to increment
    let gen2 = loop {
        let gen = read_generation().context("failed to read generation (2)")?;
        if gen == gen1 {
            // Generation not updated yet, sleep briefly
            std::thread::sleep(Duration::from_micros(10));
            continue;
        }
        break gen;
    };

    // Verify generation incremented by exactly 1
    if gen2 != gen1 + 1 {
        bail!("concurrent quote generation detected: gen1={gen1}, gen2={gen2}");
    }

    // Read quote from outblob with retry
    let mut quote = vec![0u8; QUOTE_BUF_SIZE];
    let mut quote_len = 0;
    let mut last_err = None;

    for retry in 0..MAX_RETRIES {
        match fs::File::open(format!("{CONFIGFS_PATH}/outblob")) {
            Ok(mut file) => match file.read(&mut quote) {
                Ok(len) => {
                    quote_len = len;
                    last_err = None;
                    break;
                }
                Err(e) => {
                    last_err = Some(e);
                    if retry < MAX_RETRIES - 1 {
                        std::thread::sleep(RETRY_DELAY);
                    }
                }
            },
            Err(e) => {
                last_err = Some(e);
                if retry < MAX_RETRIES - 1 {
                    std::thread::sleep(RETRY_DELAY);
                }
            }
        }
    }

    if let Some(err) = last_err {
        bail!("failed to read outblob after {MAX_RETRIES} retries: {err}");
    }

    // Validate quote size
    if quote_len == 0 {
        bail!("empty quote returned from configfs");
    }

    if quote_len < QUOTE_MIN_SIZE {
        bail!("quote too small: got {quote_len} bytes, minimum {QUOTE_MIN_SIZE}");
    }

    if quote_len == QUOTE_BUF_SIZE {
        bail!("quote may be truncated: exactly {QUOTE_BUF_SIZE} bytes");
    }

    // Verify generation hasn't changed (no concurrent access)
    let gen3 = read_generation().context("failed to read generation (3)")?;
    if gen3 != gen2 {
        bail!("concurrent quote generation detected after read: gen2={gen2}, gen3={gen3}");
    }

    // Truncate to actual size
    quote.truncate(quote_len);

    Ok(quote)
}
