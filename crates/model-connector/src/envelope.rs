use std::io::{Read, Write};

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::contract::{
    ContractError, ENVELOPE_SCHEMA_ID, TransportInvocation, TransportKey, TransportResult,
    canonical_invocation_bytes, require_id,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnvelopeKind {
    Invocation,
    Result,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportEnvelope {
    pub schema_id: String,
    pub caller_runtime_id: String,
    pub request_id: String,
    pub message_kind: EnvelopeKind,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

pub fn encrypt_invocation(
    invocation: &TransportInvocation,
    security: &TransportKey,
) -> Result<TransportEnvelope, ServiceError> {
    let plaintext = canonical_invocation_bytes(invocation)?;
    encrypt_message(
        &invocation.caller_runtime_id,
        invocation.request_id(),
        EnvelopeKind::Invocation,
        &plaintext,
        security,
    )
}

pub fn decrypt_invocation(
    envelope: &TransportEnvelope,
    security: &TransportKey,
) -> Result<TransportInvocation, ServiceError> {
    validate_envelope(envelope, EnvelopeKind::Invocation)?;
    let plaintext = decrypt_message(envelope, security)?;
    let invocation: TransportInvocation =
        rmp_serde::from_slice(&plaintext).map_err(|_| ServiceError::Encoding)?;
    if invocation.caller_runtime_id != envelope.caller_runtime_id
        || invocation.request_id() != envelope.request_id
    {
        return Err(ServiceError::OuterIdentity);
    }
    Ok(invocation)
}

pub fn encrypt_result(
    result: &TransportResult,
    security: &TransportKey,
) -> Result<TransportEnvelope, ServiceError> {
    let plaintext = rmp_serde::to_vec(result).map_err(|_| ServiceError::Encoding)?;
    encrypt_message(
        &result.caller_runtime_id,
        &result.request_id,
        EnvelopeKind::Result,
        &plaintext,
        security,
    )
}

pub fn decrypt_result(
    envelope: &TransportEnvelope,
    security: &TransportKey,
    invocation: &TransportInvocation,
) -> Result<TransportResult, ServiceError> {
    validate_envelope(envelope, EnvelopeKind::Result)?;
    let plaintext = decrypt_message(envelope, security)?;
    let result: TransportResult =
        rmp_serde::from_slice(&plaintext).map_err(|_| ServiceError::Encoding)?;
    if result.caller_runtime_id != envelope.caller_runtime_id
        || result.request_id != envelope.request_id
    {
        return Err(ServiceError::OuterIdentity);
    }
    result.validate_against(invocation)?;
    Ok(result)
}

#[derive(Debug)]
pub(crate) enum TransportFrameError {
    Connection(std::io::Error),
    Size,
}

pub(crate) fn read_transport_frame(
    reader: &mut impl Read,
    max_frame_bytes: usize,
) -> Result<Vec<u8>, TransportFrameError> {
    let mut length = [0_u8; 4];
    reader
        .read_exact(&mut length)
        .map_err(TransportFrameError::Connection)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > max_frame_bytes {
        return Err(TransportFrameError::Size);
    }
    let mut payload = vec![0_u8; length];
    reader
        .read_exact(&mut payload)
        .map_err(TransportFrameError::Connection)?;
    Ok(payload)
}

pub(crate) fn write_transport_frame(
    writer: &mut impl Write,
    payload: &[u8],
    max_frame_bytes: usize,
) -> Result<(), TransportFrameError> {
    if payload.is_empty() || payload.len() > max_frame_bytes || payload.len() > u32::MAX as usize {
        return Err(TransportFrameError::Size);
    }
    writer
        .write_all(&(payload.len() as u32).to_be_bytes())
        .and_then(|()| writer.write_all(payload))
        .and_then(|()| writer.flush())
        .map_err(TransportFrameError::Connection)
}

pub(crate) fn encrypt_message(
    caller_runtime_id: &str,
    request_id: &str,
    message_kind: EnvelopeKind,
    plaintext: &[u8],
    security: &TransportKey,
) -> Result<TransportEnvelope, ServiceError> {
    require_id(caller_runtime_id, "caller_runtime_id")?;
    require_id(request_id, "request_id")?;
    let mut nonce = [0; 12];
    OsRng.fill_bytes(&mut nonce);
    let cipher = Aes256Gcm::new_from_slice(&security.0).map_err(|_| ServiceError::Encryption)?;
    let aad = envelope_aad(
        ENVELOPE_SCHEMA_ID,
        caller_runtime_id,
        request_id,
        message_kind,
    )?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| ServiceError::Encryption)?;
    Ok(TransportEnvelope {
        schema_id: ENVELOPE_SCHEMA_ID.to_string(),
        caller_runtime_id: caller_runtime_id.to_string(),
        request_id: request_id.to_string(),
        message_kind,
        nonce,
        ciphertext,
    })
}

pub(crate) fn decrypt_message(
    envelope: &TransportEnvelope,
    security: &TransportKey,
) -> Result<Vec<u8>, ServiceError> {
    let cipher = Aes256Gcm::new_from_slice(&security.0).map_err(|_| ServiceError::Encryption)?;
    let aad = envelope_aad(
        &envelope.schema_id,
        &envelope.caller_runtime_id,
        &envelope.request_id,
        envelope.message_kind,
    )?;
    cipher
        .decrypt(
            Nonce::from_slice(&envelope.nonce),
            Payload {
                msg: &envelope.ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| ServiceError::Encryption)
}

pub(crate) fn envelope_aad(
    schema_id: &str,
    caller_runtime_id: &str,
    request_id: &str,
    message_kind: EnvelopeKind,
) -> Result<Vec<u8>, ServiceError> {
    rmp_serde::to_vec(&(schema_id, caller_runtime_id, request_id, message_kind))
        .map_err(|_| ServiceError::Encoding)
}

pub(crate) fn validate_envelope(
    envelope: &TransportEnvelope,
    expected_kind: EnvelopeKind,
) -> Result<(), ServiceError> {
    if envelope.schema_id != ENVELOPE_SCHEMA_ID || envelope.message_kind != expected_kind {
        return Err(ServiceError::Envelope);
    }
    require_id(&envelope.caller_runtime_id, "caller_runtime_id")?;
    require_id(&envelope.request_id, "request_id")?;
    if envelope.ciphertext.is_empty() {
        return Err(ServiceError::Envelope);
    }
    Ok(())
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ServiceError {
    #[error(transparent)]
    Contract(#[from] ContractError),
    #[error("invalid caller admission")]
    InvalidAdmission,
    #[error("caller runtime was admitted twice")]
    DuplicateCaller,
    #[error("callers must not share transport keys")]
    SharedCallerKey,
    #[error("connector replay store failed: {0}")]
    ReplayStore(String),
    #[error("connector replay record is malformed")]
    InvalidReplayRecord,
    #[error("caller key changed while durable replay records still exist")]
    ReplayCallerKeyMismatch,
    #[error("caller runtime is not admitted")]
    CallerNotAdmitted,
    #[error("unexpected transport envelope")]
    Envelope,
    #[error("transport envelope identity substitution")]
    OuterIdentity,
    #[error("transport encryption or authentication failed")]
    Encryption,
    #[error("transport MessagePack encoding failed")]
    Encoding,
    #[error("completion did not carry a transported provider outcome")]
    InvalidCompletion,
    #[error("completion has no active request")]
    NoActiveRequest,
    #[error("completion does not match the active request")]
    ActiveRequestMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::*;

    #[test]
    fn encrypted_invocation_hides_content_and_binds_outer_identity() {
        let invocation = invocation();
        let epiphany_key = security("epiphany-distinct-test-key");
        let envelope = encrypt_invocation(&invocation, &epiphany_key).unwrap();
        assert!(
            !envelope
                .ciphertext
                .windows("Projected state".len())
                .any(|window| window == b"Projected state")
        );
        assert_eq!(
            decrypt_invocation(&envelope, &epiphany_key).unwrap(),
            invocation
        );
        assert_eq!(
            decrypt_invocation(&envelope, &security("wrong-caller-key")),
            Err(ServiceError::Encryption)
        );

        let mut substituted = envelope;
        substituted.request_id = "request-2".to_string();
        assert_eq!(
            decrypt_invocation(&substituted, &epiphany_key),
            Err(ServiceError::Encryption)
        );
    }

    fn sealed_invocation(caller: &str, request_id: &str, kind: EnvelopeKind) -> TransportEnvelope {
        let invocation = invocation();
        let plaintext = canonical_invocation_bytes(&invocation).unwrap();
        encrypt_message(
            caller,
            request_id,
            kind,
            &plaintext,
            &security("epiphany-distinct-test-key"),
        )
        .unwrap()
    }

    #[test]
    fn the_outer_identity_must_match_the_sealed_invocation_on_each_field() {
        let key = security("epiphany-distinct-test-key");
        let invocation = invocation();
        let caller = invocation.caller_runtime_id.clone();
        let request_id = invocation.request_id().to_string();
        let matching = sealed_invocation(&caller, &request_id, EnvelopeKind::Invocation);
        assert_eq!(decrypt_invocation(&matching, &key).unwrap(), invocation);
        for envelope in [
            sealed_invocation("other-caller", &request_id, EnvelopeKind::Invocation),
            sealed_invocation(&caller, "other-request", EnvelopeKind::Invocation),
        ] {
            assert_eq!(
                decrypt_invocation(&envelope, &key),
                Err(ServiceError::OuterIdentity)
            );
        }
    }

    #[test]
    fn the_outer_identity_must_match_the_sealed_result_on_each_field() {
        let key = security("epiphany-distinct-test-key");
        let invocation = invocation();
        let result = TransportResult::transported(&invocation, Vec::new(), receipt(&invocation));
        let plaintext = rmp_serde::to_vec(&result).unwrap();
        let seal = |caller: &str, request_id: &str| {
            encrypt_message(caller, request_id, EnvelopeKind::Result, &plaintext, &key).unwrap()
        };
        let caller = result.caller_runtime_id.clone();
        let request_id = result.request_id.clone();
        assert_eq!(
            decrypt_result(&seal(&caller, &request_id), &key, &invocation).unwrap(),
            result
        );
        for envelope in [
            seal("other-caller", &request_id),
            seal(&caller, "other-request"),
        ] {
            assert_eq!(
                decrypt_result(&envelope, &key, &invocation),
                Err(ServiceError::OuterIdentity)
            );
        }
    }

    #[test]
    fn a_malformed_envelope_is_refused_before_any_decryption() {
        let key = security("epiphany-distinct-test-key");
        let invocation = invocation();
        let good = encrypt_invocation(&invocation, &key).unwrap();

        let mut schema = good.clone();
        schema.schema_id = "gamecult.codex.transport_envelope.v1".to_string();
        let wrong_kind = sealed_invocation("epiphany-yggdrasil", "request-1", EnvelopeKind::Result);
        let mut empty = good.clone();
        empty.ciphertext.clear();
        for envelope in [schema, wrong_kind, empty] {
            assert_eq!(
                decrypt_invocation(&envelope, &key),
                Err(ServiceError::Envelope)
            );
        }
        for field in ["caller_runtime_id", "request_id"] {
            let mut blank = good.clone();
            if field == "caller_runtime_id" {
                blank.caller_runtime_id = " ".to_string();
            } else {
                blank.request_id = String::new();
            }
            assert_eq!(
                decrypt_invocation(&blank, &key),
                Err(ServiceError::Contract(ContractError::Invalid(field)))
            );
        }
    }

    #[test]
    fn a_frame_is_bounded_inclusively_and_never_empty() {
        use std::io::Cursor;
        let read = |length: u32, body: usize, max: usize| {
            let mut frame = length.to_be_bytes().to_vec();
            frame.extend(vec![1; body]);
            read_transport_frame(&mut Cursor::new(frame), max)
        };
        assert_eq!(read(16, 16, 16).unwrap(), vec![1; 16]);
        assert!(matches!(read(17, 17, 16), Err(TransportFrameError::Size)));
        assert!(matches!(read(0, 0, 16), Err(TransportFrameError::Size)));
        // A bound above the length never turns an empty frame into an empty payload.
        assert!(matches!(read(0, 0, 1_000), Err(TransportFrameError::Size)));

        let write = |payload: &[u8], max: usize| {
            let mut out = Vec::new();
            write_transport_frame(&mut out, payload, max).map(|()| out)
        };
        assert_eq!(write(&[1; 16], 16).unwrap().len(), 20);
        assert!(matches!(
            write(&[1; 17], 16),
            Err(TransportFrameError::Size)
        ));
        assert!(matches!(write(&[], 16), Err(TransportFrameError::Size)));
        assert!(matches!(write(&[], 1_000), Err(TransportFrameError::Size)));
    }
}
