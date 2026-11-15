// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::vec::Vec;
use pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, SubjectPublicKeyInfoDer};
use symcrypt_core::{
    ecc::{Curve, Key},
    encoding,
    hash::Algorithm,
};
use zeroize::Zeroizing;

use crate::{Error, Result};

pub struct VerificationAlgorithm {
    curve: Curve,
    hash: Algorithm,
    asn1: bool,
}

pub static ECDSA_P256_SHA256_ASN1: VerificationAlgorithm = VerificationAlgorithm {
    curve: Curve::P256,
    hash: Algorithm::Sha256,
    asn1: true,
};
pub static ECDSA_P256_SHA256_FIXED: VerificationAlgorithm = VerificationAlgorithm {
    curve: Curve::P256,
    hash: Algorithm::Sha256,
    asn1: false,
};
pub static ECDSA_P256_SHA384_ASN1: VerificationAlgorithm = VerificationAlgorithm {
    curve: Curve::P256,
    hash: Algorithm::Sha384,
    asn1: true,
};
pub static ECDSA_P384_SHA256_ASN1: VerificationAlgorithm = VerificationAlgorithm {
    curve: Curve::P384,
    hash: Algorithm::Sha256,
    asn1: true,
};
pub static ECDSA_P384_SHA384_ASN1: VerificationAlgorithm = VerificationAlgorithm {
    curve: Curve::P384,
    hash: Algorithm::Sha384,
    asn1: true,
};
pub static ECDSA_P384_SHA384_FIXED: VerificationAlgorithm = VerificationAlgorithm {
    curve: Curve::P384,
    hash: Algorithm::Sha384,
    asn1: false,
};

pub struct EcdsaPk {
    pk: Zeroizing<Vec<u8>>,
    key: spin::Mutex<Key>,
    spki: Vec<u8>,
}

impl core::fmt::Debug for EcdsaPk {
    fn fmt(&self, _f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        Ok(())
    }
}

impl EcdsaPk {
    pub fn new() -> Result<Self> {
        let key = Key::generate(Curve::P384).map_err(|_| Error::GenerateKeyPair)?;
        let pk = key.to_pkcs8().map_err(|_| Error::GenerateKeyPair)?;
        let spki = key.to_spki().map_err(|_| Error::GenerateKeyPair)?;
        Ok(Self {
            pk,
            key: spin::Mutex::new(key),
            spki,
        })
    }

    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let signature = self
            .key
            .lock()
            .sign(Algorithm::Sha384, data)
            .map_err(|_| Error::EcdsaSign)?;
        encoding::ecdsa_signature_to_der(Curve::P384, &signature).map_err(|_| Error::EcdsaSign)
    }

    pub fn private_key(&self) -> &[u8] {
        self.pk.as_ref()
    }

    pub fn public_key(&self) -> Result<Vec<u8>> {
        self.key
            .lock()
            .public_key()
            .map_err(|_| Error::GenerateKeyPair)
    }

    pub fn public_key_spki(&self) -> Vec<u8> {
        self.spki.clone()
    }
}

pub fn ecdsa_verify(public_key: &[u8], data: &[u8], signature: &[u8]) -> Result<()> {
    ecdsa_verify_with_algorithm(public_key, data, signature, &ECDSA_P384_SHA384_ASN1)
}

pub fn ecdsa_verify_with_algorithm(
    public_key: &[u8],
    data: &[u8],
    signature: &[u8],
    algorithm: &'static VerificationAlgorithm,
) -> Result<()> {
    let mut key =
        Key::from_sec1_public_key(algorithm.curve, public_key).map_err(|_| Error::EcdsaVerify)?;
    let decoded;
    let signature = if algorithm.asn1 {
        decoded = encoding::ecdsa_signature_from_der(algorithm.curve, signature)
            .map_err(|_| Error::EcdsaVerify)?;
        &decoded
    } else {
        signature
    };
    key.verify(algorithm.hash, data, signature)
        .map_err(|_| Error::EcdsaVerify)
}

pub fn ecdsa_verify_with_raw_public_key(
    public_key: &[u8],
    data: &[u8],
    signature: &[u8],
) -> Result<()> {
    ecdsa_verify_with_algorithm(public_key, data, signature, &ECDSA_P384_SHA384_FIXED)
}

pub fn ecdsa_sign(pkcs8: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    encoding::ecdsa_signature_to_der(Curve::P384, &ecdsa_sign_fixed(pkcs8, data)?)
        .map_err(|_| Error::EcdsaSign)
}

pub fn ecdsa_sign_fixed(pkcs8: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let mut key = Key::from_pkcs8(pkcs8).map_err(|_| Error::EcdsaSign)?;
    if key.curve() != Curve::P384 {
        return Err(Error::EcdsaSign);
    }
    key.sign(Algorithm::Sha384, data)
        .map_err(|_| Error::EcdsaSign)
}

pub fn pem_to_der_from_slice(pem_data: &[u8]) -> Result<Vec<u8>> {
    if let Ok(cert) = CertificateDer::from_pem_slice(pem_data) {
        return Ok(cert.to_vec());
    }
    if let Ok(key) = PrivateKeyDer::from_pem_slice(pem_data) {
        let key = Zeroizing::new(key);
        return Ok(key.secret_der().to_vec());
    }
    if let Ok(spki) = SubjectPublicKeyInfoDer::from_pem_slice(pem_data) {
        return Ok(spki.to_vec());
    }
    Err(Error::DecodePemCert)
}

#[test]
fn test_ecdsa() {
    let ecdsa = EcdsaPk::new().unwrap();
    let data = b"test_data";
    let sig = ecdsa.sign(data).unwrap();
    let pub_key = ecdsa.public_key().unwrap();
    assert!(ecdsa_verify(&pub_key, data, &sig).is_ok());
    assert!(ecdsa.private_key().len() <= 185);
    let fixed = ecdsa_sign_fixed(ecdsa.private_key(), data).unwrap();
    assert_eq!(fixed.len(), 96);
    ecdsa_verify_with_raw_public_key(&pub_key, data, &fixed).unwrap();
    assert!(ecdsa_verify_with_raw_public_key(&pub_key, b"changed", &fixed).is_err());
    assert_eq!(
        Key::from_spki(&ecdsa.public_key_spki())
            .unwrap()
            .public_key()
            .unwrap(),
        pub_key
    );
}
