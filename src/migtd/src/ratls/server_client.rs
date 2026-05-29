// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::vec::Vec;
use async_io::{AsyncRead, AsyncWrite};
use crypto::{
    ecdsa::EcdsaPk,
    hash::digest_sha384,
    tls::{SecureChannel, TlsConfig},
    x509::{
        AlgorithmIdentifier, AnyRef, BitStringRef, Certificate, CertificateBuilder, Decode, Encode,
        ExtendedKeyUsage, Extension, Extensions, Tag,
    },
    Error as CryptoError,
};
use tdx_tdcall::tdreport::TdxReport;

use super::*;
use crate::event_log::get_event_log;
use crate::migration::pre_session_data::LogErr;
#[cfg(feature = "policy_v2")]
use crate::{migration::pre_session_data::local_peer_data, migration::servtd_ext::ServtdExt};
use verify::*;

type Result<T> = core::result::Result<T, RatlsError>;

#[cfg(not(feature = "policy_v2"))]
pub fn server<T: AsyncRead + AsyncWrite + Unpin>(stream: T) -> Result<SecureChannel<T>> {
    let signing_key = EcdsaPk::new().log_err("server EcdsaPk::new()")?;
    let (certs, quote) =
        create_certificate_for_server(&signing_key).log_err("server gen_cert()")?;
    let certs = vec![certs];

    // Server verifies certificate of client
    let config = TlsConfig::new(certs, signing_key, verify_client_cert, quote)
        .log_err("server TlsConfig::new()")?;

    config
        .tls_server(stream)
        .log_err("server tls_server()")
        .map_err(Into::into)
}

#[cfg(feature = "policy_v2")]
pub fn server<T: AsyncRead + AsyncWrite + Unpin>(
    stream: T,
    peer_data: Vec<u8>,
) -> Result<SecureChannel<T>> {
    let signing_key = EcdsaPk::new().log_err("server policy_v2 EcdsaPk::new()")?;
    let (certs, _quote) =
        create_certificate_for_server(&signing_key).log_err("server policy_v2 gen_cert()")?;
    let certs = vec![certs];

    // Server verifies certificate of client
    let config = TlsConfig::new(
        certs,
        signing_key,
        move |cert, quote| verify_client_cert(cert, quote),
        peer_data,
    )
    .log_err("server policy_v2 TlsConfig::new()")?;
    config
        .tls_server(stream)
        .log_err("server policy_v2 tls_server()")
        .map_err(Into::into)
}

#[cfg(not(feature = "policy_v2"))]
pub fn client<T: AsyncRead + AsyncWrite + Unpin>(stream: T) -> Result<SecureChannel<T>> {
    let signing_key = EcdsaPk::new().log_err("client EcdsaPk::new()")?;
    let (certs, quote) =
        create_certificate_for_client(&signing_key).log_err("client gen_cert()")?;
    let certs = vec![certs];

    // Client verifies certificate of server
    let config = TlsConfig::new(certs, signing_key, verify_server_cert, quote)
        .log_err("client TlsConfig::new()")?;
    config
        .tls_client(stream)
        .log_err("server_client client(): Failure in tls_client()")
        .map_err(Into::into)
}

#[cfg(feature = "policy_v2")]
pub fn client<T: AsyncRead + AsyncWrite + Unpin>(
    stream: T,
    peer_data: Vec<u8>,
) -> Result<SecureChannel<T>> {
    let signing_key = EcdsaPk::new().log_err("client policy_v2 EcdsaPk::new()")?;
    let (certs, _quote) =
        create_certificate_for_client(&signing_key).log_err("client policy_v2 gen_cert()")?;
    let certs = vec![certs];

    // Client verifies certificate of server
    let config = TlsConfig::new(certs, signing_key, verify_server_cert, peer_data)
        .log_err("client policy_v2 TlsConfig::new()")?;
    config
        .tls_client(stream)
        .log_err("client policy_v2 tls_client()")
        .map_err(Into::into)
}

// TLS server for rebinding new
#[cfg(feature = "policy_v2")]
pub fn server_rebinding<T: AsyncRead + AsyncWrite + Unpin>(
    stream: T,
    peer_data: Vec<u8>,
) -> Result<SecureChannel<T>> {
    let signing_key = EcdsaPk::new().log_err("server rebinding EcdsaPk::new()")?;
    let certs = create_certificate_for_rebinding_new(&signing_key)
        .log_err("server rebinding gen_cert()")?;
    let certs = vec![certs];

    let config = TlsConfig::new(certs, signing_key, verify_rebinding_old_cert, peer_data)
        .log_err("server rebinding TlsConfig::new()")?;
    config
        .tls_server(stream)
        .log_err("server rebinding tls_server()")
        .map_err(Into::into)
}

// TLS client for rebinding old
#[cfg(feature = "policy_v2")]
pub fn client_rebinding<T: AsyncRead + AsyncWrite + Unpin>(
    stream: T,
    peer_data: Vec<u8>,
    init_tdinfo: &[u8],
    servtd_ext: &ServtdExt,
) -> Result<SecureChannel<T>> {
    let signing_key = EcdsaPk::new().log_err("client rebinding EcdsaPk::new()")?;
    let certs = create_certificate_for_rebinding_old(&signing_key, init_tdinfo, servtd_ext)
        .log_err("client rebinding gen_cert()")?;
    let certs = vec![certs];

    let config = TlsConfig::new(certs, signing_key, verify_rebinding_new_cert, peer_data)
        .log_err("client rebinding TlsConfig::new()")?;
    config
        .tls_client(stream)
        .log_err("client rebinding tls_client()")
        .map_err(Into::into)
}

fn prepare_report_data(public_key: &[u8]) -> Result<[u8; 64]> {
    let hash = digest_sha384(public_key).log_err("Failed to compute SHA384 digest")?;

    let mut additional_data = [0u8; 64];
    additional_data[..hash.len()].copy_from_slice(hash.as_ref());
    Ok(additional_data)
}

fn gen_quote(public_key: &[u8]) -> Result<Vec<u8>> {
    let additional_data = prepare_report_data(public_key)?;

    let (quote, _report) = crate::quote::get_quote_with_retry(&additional_data).map_err(|e| {
        log::error!("get_quote_with_retry failed: {:?}\n", e);
        RatlsError::GetQuote
    })?;

    Ok(quote)
}

pub fn gen_tdreport(public_key: &[u8]) -> Result<TdxReport> {
    let additional_data = prepare_report_data(public_key)?;

    // Generate the TD Report that contains the public key hash as nonce
    tdx_tdcall::tdreport::tdcall_report(&additional_data)
        .log_err("Failed to get TD report via tdcall")
        .map_err(Into::into)
}

fn create_certificate_for_server(signing_key: &EcdsaPk) -> Result<(Vec<u8>, Vec<u8>)> {
    let pub_key = signing_key
        .public_key()
        .log_err("gen_cert signing_key.public_key()")?;
    let quote = gen_quote(&pub_key).log_err("gen_cert gen_quote()")?;

    #[cfg(feature = "policy_v2")]
    let policy_hash = {
        let blob = local_peer_data().ok_or_else(|| {
            log::error!(
                "gen_cert server policy_v2 Failed to build peer_data blob for policy hash.\n"
            );
            RatlsError::InvalidPolicy
        })?;
        digest_sha384(&blob)
    }
    .log_err("gen_cert digest_sha384()")?;

    let eku = create_eku()?;
    let key_usage = create_key_usage()?;

    let x509_builder = create_tls_tbs_common(&pub_key, &key_usage, &eku)?
        .add_extension(
            Extension::new(
                EXTNID_MIGTD_QUOTE_REPORT,
                Some(false),
                Some(quote.as_slice()),
            )
            .log_err("gen_cert Extension::new for EXTNID_MIGTD_QUOTE_REPORT")?,
        )
        .log_err("gen_cert add_extension for EXTNID_MIGTD_QUOTE_REPORT")?;

    // If policy_v2 feature is enabled, add policy extension
    #[cfg(feature = "policy_v2")]
    let x509_builder = x509_builder
        .add_extension(
            Extension::new(EXTNID_MIGTD_POLICY_HASH, Some(false), Some(&policy_hash)).map_err(
                |e| {
                    log::error!(
                        "gen_cert policy_v2 add_extension failed with error {:?}.\n",
                        e
                    );
                    e
                },
            )?,
        )
        .log_err("gen_cert policy_v2 add_extension for policy hash")?;

    let x509_cert_der = sign_tls_tbs(x509_builder, &signing_key)?;
    Ok((x509_cert_der, quote))
}

fn create_certificate_for_client(signing_key: &EcdsaPk) -> Result<(Vec<u8>, Vec<u8>)> {
    let pub_key = signing_key
        .public_key()
        .log_err("gen_cert signing_key.public_key()")?;
    let quote = gen_quote(&pub_key).log_err("gen_cert gen_quote()")?;

    #[cfg(feature = "policy_v2")]
    let policy_hash = {
        let blob = local_peer_data().ok_or_else(|| {
            log::error!(
                "gen_cert client policy_v2 Failed to build peer_data blob for policy hash.\n"
            );
            RatlsError::InvalidPolicy
        })?;
        digest_sha384(&blob)
    }
    .log_err("gen_cert digest_sha384()")?;

    let eku = create_eku()?;
    let key_usage = create_key_usage()?;

    let x509_builder = create_tls_tbs_common(&pub_key, &key_usage, &eku)?
        .add_extension(
            Extension::new(
                EXTNID_MIGTD_QUOTE_REPORT,
                Some(false),
                Some(quote.as_slice()),
            )
            .log_err("gen_cert Extension::new for EXTNID_MIGTD_QUOTE_REPORT")?,
        )
        .log_err("gen_cert add_extension for EXTNID_MIGTD_QUOTE_REPORT")?;

    // If policy_v2 feature is enabled, add policy extension
    #[cfg(feature = "policy_v2")]
    let x509_builder = x509_builder
        .add_extension(
            Extension::new(EXTNID_MIGTD_POLICY_HASH, Some(false), Some(&policy_hash)).map_err(
                |e| {
                    log::error!(
                        "gen_cert policy_v2 add_extension failed with error {:?}.\n",
                        e
                    );
                    e
                },
            )?,
        )
        .log_err("gen_cert policy_v2 add_extension for policy hash")?;

    let x509_cert_der = sign_tls_tbs(x509_builder, &signing_key)?;
    Ok((x509_cert_der, quote))
}

#[cfg(feature = "policy_v2")]
fn create_certificate_for_rebinding_old(
    signing_key: &EcdsaPk,
    init_tdinfo: &[u8],
    servtd_ext: &ServtdExt,
) -> Result<Vec<u8>> {
    let pub_key = signing_key
        .public_key()
        .log_err("gen_cert signing_key.public_key()")?;
    let tdreport = gen_tdreport(&pub_key).log_err("gen_cert gen_tdreport()")?;

    let blob = local_peer_data().ok_or_else(|| {
        log::error!(
            "gen_cert rebinding old policy_v2 Failed to build peer_data blob for policy hash.\n"
        );
        RatlsError::InvalidPolicy
    })?;
    let policy_hash = digest_sha384(&blob).log_err("gen_cert digest_sha384()")?;

    let eku = create_eku()?;
    let key_usage = create_key_usage()?;

    let x509_builder = create_tls_tbs_common(&pub_key, &key_usage, &eku)?
        .add_extension(
            Extension::new(
                EXTNID_MIGTD_TDREPORT,
                Some(false),
                Some(tdreport.as_bytes()),
            )
            .log_err("gen_cert Extension::new for EXTNID_MIGTD_TDREPORT")?,
        )
        .log_err("gen_cert add_extension for EXTNID_MIGTD_TDREPORT")?;

    // If policy_v2 feature is enabled, add policy extension
    #[cfg(feature = "policy_v2")]
    let x509_builder = x509_builder
        .add_extension(
            Extension::new(EXTNID_MIGTD_POLICY_HASH, Some(false), Some(&policy_hash)).map_err(
                |e| {
                    log::error!(
                        "gen_cert policy_v2 add_extension failed with error {:?}.\n",
                        e
                    );
                    e
                },
            )?,
        )
        .log_err("gen_cert policy_v2 add_extension for policy hash")?
        .add_extension(
            Extension::new(
                EXTNID_MIGTD_SERVTD_EXT,
                Some(false),
                Some(servtd_ext.as_bytes()),
            )
            .log_err("gen_cert policy_v2 add_extension")?,
        )
        .log_err("gen_cert policy_v2 add_extension for servtd_ext")?
        .add_extension(
            Extension::new(EXTNID_MIGTD_TDREPORT_INIT, Some(false), Some(&init_tdinfo)).map_err(
                |e| {
                    log::error!(
                        "gen_cert policy_v2 add_extension failed with error {:?}.\n",
                        e
                    );
                    e
                },
            )?,
        )
        .log_err("gen_cert policy_v2 add_extension for tdreport init")?;

    let x509_cert_der = sign_tls_tbs(x509_builder, &signing_key)?;
    Ok(x509_cert_der)
}

#[cfg(feature = "policy_v2")]
fn create_certificate_for_rebinding_new(signing_key: &EcdsaPk) -> Result<Vec<u8>> {
    let pub_key = signing_key
        .public_key()
        .log_err("gen_cert signing_key.public_key()")?;
    let tdreport = gen_tdreport(&pub_key).log_err("gen_cert gen_quote()")?;

    let policy_hash = {
        let blob = local_peer_data().ok_or_else(|| {
            log::error!(
                "gen_cert rebinding new policy_v2 Failed to build peer_data blob for policy hash.\n"
            );
            RatlsError::InvalidPolicy
        })?;
        digest_sha384(&blob)
    }
    .log_err("gen_cert digest_sha384()")?;

    let eku = create_eku()?;
    let key_usage = create_key_usage()?;

    let x509_builder = create_tls_tbs_common(&pub_key, &key_usage, &eku)?
        .add_extension(
            Extension::new(
                EXTNID_MIGTD_TDREPORT,
                Some(false),
                Some(tdreport.as_bytes()),
            )
            .log_err("gen_cert Extension::new for EXTNID_MIGTD_TDREPORT")?,
        )
        .log_err("gen_cert add_extension for EXTNID_MIGTD_TDREPORT")?;

    let x509_builder = x509_builder
        .add_extension(
            Extension::new(EXTNID_MIGTD_POLICY_HASH, Some(false), Some(&policy_hash)).map_err(
                |e| {
                    log::error!(
                        "gen_cert policy_v2 add_extension failed with error {:?}.\n",
                        e
                    );
                    e
                },
            )?,
        )
        .log_err("gen_cert policy_v2 add_extension for policy hash")?;

    let x509_cert_der = sign_tls_tbs(x509_builder, &signing_key)?;
    Ok(x509_cert_der)
}

fn create_tls_tbs_common<'a>(
    public_key: &'a [u8],
    key_usage: &'a [u8],
    eku: &'a [u8],
) -> Result<CertificateBuilder<'a>> {
    let algorithm = AlgorithmIdentifier {
        algorithm: ID_EC_PUBKEY_OID,
        parameters: Some(AnyRef::new(
            Tag::ObjectIdentifier,
            SECP384R1_OID.as_bytes(),
        )?),
    };
    let sig_alg = AlgorithmIdentifier {
        algorithm: ID_EC_SIG_OID,
        parameters: None,
    };

    let event_log = get_event_log().ok_or_else(|| {
        log::error!("gen_cert get_event_log() failed with error RatlsError::InvalidEventlog.\n");
        RatlsError::InvalidEventlog
    })?;

    let x509_builder = CertificateBuilder::new(sig_alg, algorithm, public_key)
        .log_err("gen_cert CertificateBuilder::new")?
        // 1970-01-01T00:00:00Z
        .set_not_before(core::time::Duration::new(0, 0))
        .log_err("gen_cert set_not_before")?
        // 9999-12-31T23:59:59Z
        .set_not_after(core::time::Duration::new(253402300799, 0))
        .log_err("gen_cert set_not_after")?
        .add_extension(
            Extension::new(KEY_USAGE_EXTENSION, Some(true), Some(key_usage))
                .log_err("gen_cert Extension::new for KEY_USAGE_EXTENSION")?,
        )
        .log_err("gen_cert add_extension for KEY_USAGE_EXTENSION")?
        .add_extension(
            Extension::new(EXTENDED_KEY_USAGE, Some(false), Some(eku))
                .log_err("gen_cert Extension::new for EXTENDED_KEY_USAGE")?,
        )
        .log_err("gen_cert add_extension for EXTENDED_KEY_USAGE")?
        .add_extension(
            Extension::new(EXTNID_MIGTD_EVENT_LOG, Some(false), Some(event_log))
                .log_err("gen_cert Extension::new for EXTNID_MIGTD_EVENT_LOG")?,
        )
        .log_err("gen_cert add_extension for EXTNID_MIGTD_EVENT_LOG")?;

    Ok(x509_builder)
}

fn sign_tls_tbs(x509_builder: CertificateBuilder, signing_key: &EcdsaPk) -> Result<Vec<u8>> {
    let mut x509_certificate = x509_builder.build();
    let tbs = x509_certificate
        .tbs_certificate
        .to_der()
        .log_err("gen_cert x509_certificate.tbs_certificate.to_der")?;
    let signature = signing_key
        .sign(&tbs)
        .log_err("gen_cert signing_key.sign")?;
    x509_certificate
        .set_signature(&signature)
        .log_err("gen_cert x509_certificate.set_signature")?;

    Ok(x509_certificate
        .to_der()
        .log_err("gen_cert x509_certificate.to_der")?)
}

fn create_eku() -> Result<Vec<u8>> {
    Ok(vec![SERVER_AUTH, CLIENT_AUTH, MIGTD_EXTENDED_KEY_USAGE]
        .to_der()
        .log_err("gen_cert to_der")?)
}

fn create_key_usage() -> Result<Vec<u8>> {
    Ok(BitStringRef::from_bytes(&[0x80])
        .log_err("gen_cert BitStringRef::from_bytes()")?
        .to_der()
        .log_err("gen_cert BitStringRef::to_der()")?)
}

fn verify_server_cert(cert: &[u8], quote: &[u8]) -> core::result::Result<(), CryptoError> {
    verify_peer_cert(true, cert, quote)
}

fn verify_client_cert(cert: &[u8], quote: &[u8]) -> core::result::Result<(), CryptoError> {
    verify_peer_cert(false, cert, quote)
}

#[cfg(not(feature = "test_disable_ra_and_accept_all"))]
mod verify {
    use super::*;
    use crate::mig_policy;

    use alloc::string::ToString;
    use crypto::ecdsa::ecdsa_verify;
    use crypto::{Error as CryptoError, Result as CryptoResult};
    use policy::PolicyError;

    #[cfg(not(feature = "policy_v2"))]
    pub fn verify_peer_cert(
        is_client: bool,
        cert: &[u8],
        quote_local: &[u8],
    ) -> core::result::Result<(), CryptoError> {
        let verified_report_local = attestation::verify_quote(quote_local).map_err(|e| {
            log::error!("Mutual attestation error {:?}.\n", e);
            CryptoError::TlsVerifyPeerCert(MUTUAL_ATTESTATION_ERROR.to_string())
        })?;
        let cert = Certificate::from_der(cert).map_err(|e| {
            log::error!("Failed to parse certificate from DER. Error: {:?}\n", e);
            CryptoError::ParseCertificate
        })?;
        let extensions = cert.tbs_certificate.extensions.as_ref().ok_or_else(|| {
            log::error!("Failed to get certificate extensions.\n");
            CryptoError::ParseCertificate
        })?;

        // Check if extensions contain `MIGTD_EXTENDED_KEY_USAGE`
        check_migtd_eku(extensions).log_err("Failed to check MIGTD EKU")?;
        // Parse out quote report and event log from certificate extensions
        let quote_report =
            find_extension(extensions, &EXTNID_MIGTD_QUOTE_REPORT).ok_or_else(|| {
                log::error!("Failed to find quote report extension.\n");
                CryptoError::ParseCertificate
            })?;
        let event_log = find_extension(extensions, &EXTNID_MIGTD_EVENT_LOG).ok_or_else(|| {
            log::error!("Failed to find event log extension.\n");
            CryptoError::ParseCertificate
        })?;

        if let Ok(verified_report_peer) = attestation::verify_quote(quote_report) {
            verify_signature(&cert, verified_report_peer.as_slice())
                .log_err("Failed to verify signature")?;

            // MigTD-src acts as TLS client
            let policy_check_result = mig_policy::authenticate_policy(
                is_client,
                verified_report_local.as_slice(),
                verified_report_peer.as_slice(),
                event_log,
            );

            if let Err(e) = &policy_check_result {
                log::error!("Policy check failed, below is the detail information:\n");
                log::error!("{:x?}\n", e);
            }

            policy_check_result.map_err(|e| match e {
                PolicyError::InvalidPolicy => {
                    log::error!("Invalid migration policy.\n");
                    CryptoError::TlsVerifyPeerCert(INVALID_MIG_POLICY_ERROR.to_string())
                }
                _ => {
                    log::error!("Migration policy unsatisfied.\n");
                    CryptoError::TlsVerifyPeerCert(MIG_POLICY_UNSATISFIED_ERROR.to_string())
                }
            })
        } else {
            log::error!("Mutual attestation error.\n");
            Err(CryptoError::TlsVerifyPeerCert(
                MUTUAL_ATTESTATION_ERROR.to_string(),
            ))
        }
    }

    #[cfg(feature = "policy_v2")]
    pub fn verify_peer_cert(
        is_client: bool,
        cert: &[u8],
        peer_data: &[u8],
    ) -> core::result::Result<(), CryptoError> {
        let cert = Certificate::from_der(cert).map_err(|_| {
            log::error!("Failed to parse certificate from DER.\n");
            CryptoError::ParseCertificate
        })?;

        let extensions = cert.tbs_certificate.extensions.as_ref().ok_or_else(|| {
            log::error!("Failed to get certificate extensions.\n");
            CryptoError::ParseCertificate
        })?;
        // Check if extensions contain `MIGTD_EXTENDED_KEY_USAGE`
        check_migtd_eku(extensions).log_err("Failed to check MIGTD EKU")?;
        // Parse out quote, event log and policy from certificate extensions
        let quote_report =
            find_extension(extensions, &EXTNID_MIGTD_QUOTE_REPORT).ok_or_else(|| {
                log::error!("Failed to find quote report extension.\n");
                CryptoError::ParseCertificate
            })?;
        let event_log = find_extension(extensions, &EXTNID_MIGTD_EVENT_LOG).ok_or_else(|| {
            log::error!("Failed to find event log extension.\n");
            CryptoError::ParseCertificate
        })?;
        let expected_policy_hash = find_extension(extensions, &EXTNID_MIGTD_POLICY_HASH)
            .ok_or_else(|| {
                log::error!("Failed to find expected policy hash extension.\n");
                CryptoError::ParseCertificate
            })?;

        let exact_policy_hash = digest_sha384(peer_data)?;
        if expected_policy_hash != exact_policy_hash.as_slice() {
            log::error!("Invalid migration policy.\n");
            return Err(CryptoError::TlsVerifyPeerCert(
                INVALID_MIG_POLICY_ERROR.to_string(),
            ));
        }
        // MigTD-src acts as TLS client
        let policy_check_result =
            mig_policy::authenticate_remote(is_client, quote_report, peer_data, event_log);

        if let Err(e) = &policy_check_result {
            log::error!("Policy check failed, below is the detail information:\n");
            log::error!("{:x?}\n", e);
        }

        let suppl_data = policy_check_result.map_err(|e| match e {
            PolicyError::InvalidPolicy => {
                log::error!("Invalid migration policy.\n");
                CryptoError::TlsVerifyPeerCert(INVALID_MIG_POLICY_ERROR.to_string())
            }
            _ => {
                log::error!("Migration policy unsatisfied.\n");
                CryptoError::TlsVerifyPeerCert(MIG_POLICY_UNSATISFIED_ERROR.to_string())
            }
        })?;

        verify_signature(&cert, suppl_data.as_slice())
    }

    #[cfg(feature = "policy_v2")]
    pub fn verify_rebinding_old_cert(
        cert: &[u8],
        peer_data: &[u8],
    ) -> core::result::Result<(), CryptoError> {
        let cert = Certificate::from_der(cert).map_err(|_| {
            log::error!("Failed to parse certificate from DER.\n");
            CryptoError::ParseCertificate
        })?;

        let extensions = cert.tbs_certificate.extensions.as_ref().ok_or_else(|| {
            log::error!("Failed to get certificate extensions.\n");
            CryptoError::ParseCertificate
        })?;
        // Check if extensions contain `MIGTD_EXTENDED_KEY_USAGE`
        check_migtd_eku(extensions).log_err("Failed to check MIGTD EKU")?;

        let td_report = find_extension(extensions, &EXTNID_MIGTD_TDREPORT).ok_or_else(|| {
            log::error!("Failed to find tdreport extension.\n");
            CryptoError::ParseCertificate
        })?;
        let event_log = find_extension(extensions, &EXTNID_MIGTD_EVENT_LOG).ok_or_else(|| {
            log::error!("Failed to find event log extension.\n");
            CryptoError::ParseCertificate
        })?;
        let expected_policy_hash = find_extension(extensions, &EXTNID_MIGTD_POLICY_HASH)
            .ok_or_else(|| {
                log::error!("Failed to find expected policy hash extension.\n");
                CryptoError::ParseCertificate
            })?;
        // Per GHCI 1.5: init extension now carries TDINFO_STRUCT instead of full TDREPORT
        let init_tdinfo =
            find_extension(extensions, &EXTNID_MIGTD_TDREPORT_INIT).ok_or_else(|| {
                log::error!("Failed to find init tdinfo extension.\n");
                CryptoError::ParseCertificate
            })?;
        let servtd_ext = find_extension(extensions, &EXTNID_MIGTD_SERVTD_EXT).ok_or_else(|| {
            log::error!("Failed to find servtd ext extension.\n");
            CryptoError::ParseCertificate
        })?;

        let exact_policy_hash = digest_sha384(peer_data)?;
        if expected_policy_hash != exact_policy_hash.as_slice() {
            log::error!("Invalid rebinding policy.\n");
            return Err(CryptoError::TlsVerifyPeerCert(
                INVALID_MIG_POLICY_ERROR.to_string(),
            ));
        }

        let policy_check_result = mig_policy::authenticate_rebinding_old(
            td_report,
            event_log,
            peer_data,
            init_tdinfo,
            servtd_ext,
        );

        if let Err(e) = &policy_check_result {
            log::error!("Policy check failed, below is the detail information:\n");
            log::error!("{:x?}\n", e);
        }

        let suppl_data = policy_check_result.map_err(|e| match e {
            PolicyError::InvalidPolicy => {
                log::error!("Invalid rebinding policy.\n");
                CryptoError::TlsVerifyPeerCert(INVALID_MIG_POLICY_ERROR.to_string())
            }
            _ => {
                log::error!("Rebinding policy unsatisfied.\n");
                CryptoError::TlsVerifyPeerCert(MIG_POLICY_UNSATISFIED_ERROR.to_string())
            }
        })?;

        verify_signature_with_tdreport(&cert, suppl_data.as_slice())
    }

    #[cfg(feature = "policy_v2")]
    pub fn verify_rebinding_new_cert(
        cert: &[u8],
        peer_data: &[u8],
    ) -> core::result::Result<(), CryptoError> {
        let cert = Certificate::from_der(cert).map_err(|_| {
            log::error!("Failed to parse certificate from DER.\n");
            CryptoError::ParseCertificate
        })?;

        let extensions = cert.tbs_certificate.extensions.as_ref().ok_or_else(|| {
            log::error!("Failed to get certificate extensions.\n");
            CryptoError::ParseCertificate
        })?;
        // Check if extensions contain `MIGTD_EXTENDED_KEY_USAGE`
        check_migtd_eku(extensions).log_err("Failed to check MIGTD EKU")?;

        let td_report = find_extension(extensions, &EXTNID_MIGTD_TDREPORT).ok_or_else(|| {
            log::error!("Failed to find quote report extension.\n");
            CryptoError::ParseCertificate
        })?;
        let event_log = find_extension(extensions, &EXTNID_MIGTD_EVENT_LOG).ok_or_else(|| {
            log::error!("Failed to find event log extension.\n");
            CryptoError::ParseCertificate
        })?;
        let expected_policy_hash = find_extension(extensions, &EXTNID_MIGTD_POLICY_HASH)
            .ok_or_else(|| {
                log::error!("Failed to find expected policy hash extension.\n");
                CryptoError::ParseCertificate
            })?;

        let exact_policy_hash = digest_sha384(peer_data)?;
        if expected_policy_hash != exact_policy_hash.as_slice() {
            log::error!("Invalid migration policy.\n");
            return Err(CryptoError::TlsVerifyPeerCert(
                INVALID_MIG_POLICY_ERROR.to_string(),
            ));
        }

        let policy_check_result =
            mig_policy::authenticate_rebinding_new(td_report, event_log, peer_data);

        if let Err(e) = &policy_check_result {
            log::error!("Policy check failed, below is the detail information:\n");
            log::error!("{:x?}\n", e);
        }

        let suppl_data = policy_check_result.map_err(|e| match e {
            PolicyError::InvalidPolicy => {
                log::error!("Invalid rebinding policy.\n");
                CryptoError::TlsVerifyPeerCert(INVALID_MIG_POLICY_ERROR.to_string())
            }
            _ => {
                log::error!("Rebinding policy unsatisfied.\n");
                CryptoError::TlsVerifyPeerCert(MIG_POLICY_UNSATISFIED_ERROR.to_string())
            }
        })?;

        verify_signature_with_tdreport(&cert, suppl_data.as_slice())
    }

    fn verify_signature(cert: &Certificate, verified_report: &[u8]) -> CryptoResult<()> {
        let public_key = cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .ok_or_else(|| {
                log::error!("Failed to get public key bytes from certificate.\n");
                CryptoError::ParseCertificate
            })?;
        let tbs = cert
            .tbs_certificate
            .to_der()
            .log_err("Failed to get tbs_certificate der")?;
        let signature = cert.signature_value.as_bytes().ok_or_else(|| {
            log::error!("Failed to get signature bytes from certificate.\n");
            CryptoError::ParseCertificate
        })?;
        verify_public_key(verified_report, public_key).log_err("Public key verification")?;
        ecdsa_verify(public_key, &tbs, signature)
    }

    #[cfg(feature = "policy_v2")]
    fn verify_signature_with_tdreport(cert: &Certificate, tdreport: &[u8]) -> CryptoResult<()> {
        let public_key = cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .ok_or_else(|| {
                log::error!("Failed to get public key bytes from certificate.\n");
                CryptoError::ParseCertificate
            })?;
        let tbs = cert
            .tbs_certificate
            .to_der()
            .log_err("Failed to get tbs_certificate der")?;
        let signature = cert.signature_value.as_bytes().ok_or_else(|| {
            log::error!("Failed to get signature bytes from certificate.\n");
            CryptoError::ParseCertificate
        })?;
        verify_public_key_with_tdreport(tdreport, public_key).log_err("Public key verification")?;
        ecdsa_verify(public_key, &tbs, signature)
    }

    fn verify_public_key(verified_report: &[u8], public_key: &[u8]) -> CryptoResult<()> {
        if cfg!(feature = "AzCVMEmu") {
            // In AzCVMEmu mode, REPORTDATA is constructed differently.
            // Bypass public key hash check in this development environment.
            log::warn!(
                "AzCVMEmu mode: Skipping public key verification in TD report. This is NOT secure for production use.\n"
            );
            return Ok(());
        }
        if cfg!(feature = "use-mock-quote") {
            // In use-mock-quote mode, mock quote is used for testing.
            // Bypass public key hash check in this development environment.
            log::warn!(
                "use-mock-quote mode: Skipping public key verification in TD report. This is NOT secure for production use.\n"
            );
            return Ok(());
        }
        const PUBLIC_KEY_HASH_SIZE: usize = 48;

        let report_data = &verified_report[520..520 + PUBLIC_KEY_HASH_SIZE];
        let digest = digest_sha384(public_key).log_err("Failed to compute SHA384 digest")?;

        if report_data == digest.as_slice() {
            Ok(())
        } else {
            log::error!("Public key verification failed in TD report.\n");
            Err(CryptoError::TlsVerifyPeerCert(
                MISMATCH_PUBLIC_KEY.to_string(),
            ))
        }
    }

    #[cfg(feature = "policy_v2")]
    fn verify_public_key_with_tdreport(tdreport: &[u8], public_key: &[u8]) -> CryptoResult<()> {
        use tdx_tdcall::tdreport::TdxReport;
        if cfg!(feature = "AzCVMEmu") {
            // In AzCVMEmu mode, REPORTDATA is constructed differently.
            // Bypass public key hash check in this development environment.
            log::warn!(
                "AzCVMEmu mode: Skipping public key verification in TD report. This is NOT secure for production use.\n"
            );
            return Ok(());
        }
        const PUBLIC_KEY_HASH_SIZE: usize = 48;

        let tdx_report = TdxReport::read_from_bytes(tdreport).ok_or(
            CryptoError::TlsVerifyPeerCert(MISMATCH_PUBLIC_KEY.to_string()),
        )?;
        let report_data = &tdx_report.report_mac.report_data[..PUBLIC_KEY_HASH_SIZE];
        let digest = digest_sha384(public_key).log_err("Failed to compute SHA384 digest")?;

        if report_data == digest.as_slice() {
            Ok(())
        } else {
            log::error!("Public key verification failed in TD report.\n");
            Err(CryptoError::TlsVerifyPeerCert(
                MISMATCH_PUBLIC_KEY.to_string(),
            ))
        }
    }
}

// Only for test to bypass the quote verification
#[cfg(feature = "test_disable_ra_and_accept_all")]
mod verify {
    use super::*;

    pub fn verify_peer_cert(
        _is_client: bool,
        cert: &[u8],
        _quote_local: &[u8],
    ) -> core::result::Result<(), CryptoError> {
        let cert = Certificate::from_der(cert).map_err(|_| CryptoError::ParseCertificate)?;

        let extensions = cert
            .tbs_certificate
            .extensions
            .as_ref()
            .ok_or(CryptoError::ParseCertificate)?;
        // Check if extensions contain `MIGTD_EXTENDED_KEY_USAGE`
        check_migtd_eku(extensions)?;
        // Parse out quote report and event log from certificate extensions
        let quote_report = find_extension(extensions, &EXTNID_MIGTD_QUOTE_REPORT)
            .ok_or(CryptoError::ParseCertificate)?;
        let event_log = find_extension(extensions, &EXTNID_MIGTD_EVENT_LOG)
            .ok_or(CryptoError::ParseCertificate)?;

        // As the remote attestation is disabled, the certificate can't be verified. Aways return
        // success for test purpose.
        Ok(())
    }

    pub fn verify_rebinding_old_cert(
        cert: &[u8],
        pre_session_data: &[u8],
    ) -> core::result::Result<(), CryptoError> {
        Ok(())
    }

    pub fn verify_rebinding_new_cert(
        cert: &[u8],
        policy: &[u8],
    ) -> core::result::Result<(), CryptoError> {
        Ok(())
    }
}

fn check_migtd_eku(extensions: &Extensions) -> core::result::Result<(), CryptoError> {
    for extn in extensions.get() {
        if extn.extn_id == EXTENDED_KEY_USAGE {
            if let Some(extn_value) = extn.extn_value {
                let eku = ExtendedKeyUsage::from_der(extn_value.as_bytes())
                    .log_err("Failed to parse ExtendedKeyUsage")?;
                if eku.contains(&MIGTD_EXTENDED_KEY_USAGE) {
                    return Ok(());
                }
            }
        }
    }

    log::error!("check_migtd_eku MIGTD Extended Key Usage not found in certificate.\n");
    Err(CryptoError::ParseCertificate)
}

pub(crate) fn find_extension<'a>(
    extensions: &'a Extensions,
    id: &ObjectIdentifier,
) -> Option<&'a [u8]> {
    extensions.get().iter().find_map(|extn| {
        if &extn.extn_id == id {
            extn.extn_value.map(|v| v.as_bytes())
        } else {
            None
        }
    })
}
