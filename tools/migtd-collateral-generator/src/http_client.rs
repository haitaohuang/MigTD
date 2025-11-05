// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use anyhow::Result;
use curl::easy::Easy;
use std::collections::HashMap;

pub struct PcsResponse {
    pub response_code: u32,
    pub header_map: HashMap<String, String>,
    pub data: Vec<u8>,
}

pub fn fetch_data_from_url(url: &str) -> Result<PcsResponse> {
    let mut handle = Easy::new();
    let mut data = Vec::new();
    let mut http_header = Vec::new();

    handle.url(url)?;
    {
        let mut transfer = handle.transfer();
        transfer.header_function(|header_bytes| {
            http_header.extend_from_slice(header_bytes);
            true
        })?;
        transfer.write_function(|new_data| {
            data.extend_from_slice(new_data);
            Ok(new_data.len())
        })?;
        transfer.perform()?;
    }

    Ok(PcsResponse {
        response_code: handle.response_code()?,
        header_map: parse_http_headers(http_header)?,
        data,
    })
}

// Converts raw HTTP header bytes to a key-value map.
fn parse_http_headers(header_bytes: Vec<u8>) -> Result<HashMap<String, String>> {
    let mut headers = HashMap::new();
    let header_str = String::from_utf8(header_bytes)?;

    for line in header_str.lines() {
        if let Some((key, value)) = line.split_once(": ") {
            headers.insert(key.trim().to_string(), value.trim().to_string());
        }
    }

    Ok(headers)
}
