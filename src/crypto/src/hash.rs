// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::vec::Vec;
use symcrypt_core::hash::Algorithm;

use crate::{Error, Result, SHA384_DIGEST_SIZE};

pub fn digest_sha384(data: &[u8]) -> Result<Vec<u8>> {
    let digest = Algorithm::Sha384
        .digest(data)
        .map_err(|_| Error::CalculateDigest)?;

    if digest.len() != SHA384_DIGEST_SIZE {
        return Err(Error::CalculateDigest);
    }

    Ok(digest)
}
