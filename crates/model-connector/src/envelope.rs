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
    #[error("transport payload exceeds the caller bound")]
    PayloadTooLarge,
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
}
