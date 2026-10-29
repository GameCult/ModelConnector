use std::io::{Read, Write};

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use cultnet_rs::{
    CultNetMessage, CultNetWireContract, decode_cultnet_message_from_slice,
    encode_cultnet_message_to_vec,
};
use rand_core::{OsRng, RngCore};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::contract::{
    ContractError, ENVELOPE_SCHEMA_ID, TransportInvocation, TransportKey, TransportResult,
    canonical_invocation_bytes, require_id, wire_decode, wire_encode,
};
use crate::readout::SpendReadout;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum EnvelopeKind {
    Invocation,
    Result,
    SpendReadoutRequest,
    SpendReadoutResult,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TransportEnvelope {
    pub schema_id: String,
    pub caller_runtime_id: String,
    pub request_id: String,
    pub message_kind: EnvelopeKind,
    pub nonce: [u8; 12],
    #[serde(with = "serde_bytes")]
    #[schemars(schema_with = "binary_schema")]
    pub ciphertext: Vec<u8>,
}

/// Raw bytes are MessagePack `bin` on the wire, never an array of integers.
/// Serves the ciphertext and both reasoning states.
pub(crate) fn binary_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "type": "string",
        "format": "binary",
        "description": "MessagePack bin: raw bytes, never an array of integers"
    })
}

/// The CultNet service every frame of this connector addresses.
pub const CONNECTOR_SERVICE_ID: &str = "gamecult.model.connector";
/// The operation that runs one sealed invocation.
pub const INVOKE_OPERATION: &str = "invoke";
/// The operation that reads the spend ledger and the plan's quota.
pub const SPEND_READOUT_OPERATION: &str = "spend_readout";

const PAYLOAD_ENCODING: &str = "messagepack-base64";
const OK_STATUS: &str = "ok";

/// The longest caller id, request id or model name a service admits. The
/// frame arithmetic below depends on it. A request whose id is longer is
/// refused on the wire as malformed.
pub const MAX_IDENTITY_BYTES: usize = 256;

fn carriage_bytes(message: &CultNetMessage) -> Result<Vec<u8>, ServiceError> {
    encode_cultnet_message_to_vec(message, CultNetWireContract::CultNetSchemaV0)
        .map_err(|_| ServiceError::Carriage)
}

fn seal_payload(envelope: &TransportEnvelope) -> Result<String, ServiceError> {
    Ok(STANDARD.encode(wire_encode(envelope)?))
}

/// The two operations of the connector service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Operation {
    Invoke,
    SpendReadout,
}

impl Operation {
    fn name(self) -> &'static str {
        match self {
            Operation::Invoke => INVOKE_OPERATION,
            Operation::SpendReadout => SPEND_READOUT_OPERATION,
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        [Operation::Invoke, Operation::SpendReadout]
            .into_iter()
            .find(|operation| operation.name() == name)
    }
}

/// The CultNet frame a request travels in: a `cultnet.operation_request.v0`
/// for [`CONNECTOR_SERVICE_ID`] and the named operation, its `message_id` the
/// request id and its payload the base64 of the named sealed envelope.
fn request_frame(
    operation: Operation,
    envelope: &TransportEnvelope,
) -> Result<Vec<u8>, ServiceError> {
    carriage_bytes(&CultNetMessage::OperationRequest {
        message_id: envelope.request_id.clone(),
        service_id: CONNECTOR_SERVICE_ID.to_string(),
        operation: operation.name().to_string(),
        payload_schema: ENVELOPE_SCHEMA_ID.to_string(),
        payload_encoding: PAYLOAD_ENCODING.to_string(),
        payload: seal_payload(envelope)?,
        source_runtime_id: None,
        target_runtime_id: None,
    })
}

/// The CultNet frame a response travels in: a `cultnet.operation_response.v0`
/// with status `ok`, otherwise shaped like the request's.
#[cfg(any(feature = "daemon", test))]
fn response_frame(
    operation: Operation,
    envelope: &TransportEnvelope,
) -> Result<Vec<u8>, ServiceError> {
    carriage_bytes(&CultNetMessage::OperationResponse {
        message_id: envelope.request_id.clone(),
        service_id: CONNECTOR_SERVICE_ID.to_string(),
        operation: operation.name().to_string(),
        status: OK_STATUS.to_string(),
        payload_schema: ENVELOPE_SCHEMA_ID.to_string(),
        payload_encoding: PAYLOAD_ENCODING.to_string(),
        payload: seal_payload(envelope)?,
        diagnostics: Vec::new(),
        source_runtime_id: None,
    })
}

pub(crate) fn encode_invocation_frame(
    envelope: &TransportEnvelope,
) -> Result<Vec<u8>, ServiceError> {
    request_frame(Operation::Invoke, envelope)
}

pub(crate) fn encode_spend_readout_request_frame(
    envelope: &TransportEnvelope,
) -> Result<Vec<u8>, ServiceError> {
    request_frame(Operation::SpendReadout, envelope)
}

#[cfg(any(feature = "daemon", test))]
pub(crate) fn encode_result_frame(envelope: &TransportEnvelope) -> Result<Vec<u8>, ServiceError> {
    response_frame(Operation::Invoke, envelope)
}

#[cfg(feature = "daemon")]
pub(crate) fn encode_spend_readout_response_frame(
    envelope: &TransportEnvelope,
) -> Result<Vec<u8>, ServiceError> {
    response_frame(Operation::SpendReadout, envelope)
}

/// Opens the carriage of one frame. Everything the carriage says is checked
/// here, before any decryption: the service, that the operation is one this
/// service has, the payload schema, and that the message id is the sealed
/// envelope's request id.
fn open_carriage(
    message_id: &str,
    service_id: &str,
    operation: &str,
    payload_schema: &str,
    payload: &str,
) -> Result<(Operation, TransportEnvelope), ServiceError> {
    let operation = Operation::from_name(operation).ok_or(ServiceError::Carriage)?;
    if service_id != CONNECTOR_SERVICE_ID || payload_schema != ENVELOPE_SCHEMA_ID {
        return Err(ServiceError::Carriage);
    }
    let bytes = STANDARD
        .decode(payload)
        .map_err(|_| ServiceError::Carriage)?;
    let envelope: TransportEnvelope = wire_decode(&bytes).map_err(|_| ServiceError::Encoding)?;
    if envelope.request_id != message_id {
        return Err(ServiceError::OuterIdentity);
    }
    Ok((operation, envelope))
}

fn read_carriage(bytes: &[u8]) -> Result<CultNetMessage, ServiceError> {
    decode_cultnet_message_from_slice(bytes, CultNetWireContract::CultNetSchemaV0)
        .map_err(|_| ServiceError::Carriage)
}

/// A request frame, by the operation it names.
#[cfg(any(feature = "daemon", test))]
pub(crate) enum RequestFrame {
    Invoke(TransportEnvelope),
    SpendReadout(TransportEnvelope),
}

#[cfg(any(feature = "daemon", test))]
pub(crate) fn decode_request_frame(bytes: &[u8]) -> Result<RequestFrame, ServiceError> {
    match read_carriage(bytes)? {
        CultNetMessage::OperationRequest {
            message_id,
            service_id,
            operation,
            payload_schema,
            payload,
            ..
        } => {
            match open_carriage(
                &message_id,
                &service_id,
                &operation,
                &payload_schema,
                &payload,
            )? {
                (Operation::Invoke, envelope) => Ok(RequestFrame::Invoke(envelope)),
                (Operation::SpendReadout, envelope) => Ok(RequestFrame::SpendReadout(envelope)),
            }
        }
        _ => Err(ServiceError::Carriage),
    }
}

#[cfg(test)]
pub(crate) fn decode_invocation_frame(bytes: &[u8]) -> Result<TransportEnvelope, ServiceError> {
    match decode_request_frame(bytes)? {
        RequestFrame::Invoke(envelope) => Ok(envelope),
        RequestFrame::SpendReadout(_) => Err(ServiceError::Carriage),
    }
}

fn decode_response_frame(
    bytes: &[u8],
    expected: Operation,
) -> Result<TransportEnvelope, ServiceError> {
    match read_carriage(bytes)? {
        CultNetMessage::OperationResponse {
            message_id,
            service_id,
            operation,
            status,
            payload_schema,
            payload,
            ..
        } if status == OK_STATUS => {
            match open_carriage(
                &message_id,
                &service_id,
                &operation,
                &payload_schema,
                &payload,
            )? {
                (found, envelope) if found == expected => Ok(envelope),
                _ => Err(ServiceError::Carriage),
            }
        }
        _ => Err(ServiceError::Carriage),
    }
}

pub(crate) fn decode_result_frame(bytes: &[u8]) -> Result<TransportEnvelope, ServiceError> {
    decode_response_frame(bytes, Operation::Invoke)
}

pub(crate) fn decode_spend_readout_response_frame(
    bytes: &[u8],
) -> Result<TransportEnvelope, ServiceError> {
    decode_response_frame(bytes, Operation::SpendReadout)
}

/// The most bytes one frame holding a sealed envelope of `ciphertext_len`
/// ciphertext bytes can occupy, with ids at their longest: the frame a caller
/// payload bound (`CallerAdmission`'s `max_payload_bytes`, a bound on
/// ciphertext length) needs.
///
/// A frame is a CultNet operation message whose payload is the base64 of the
/// named envelope. The result frame is the larger of the two directions (it
/// also carries a status), so this bound holds for an invocation as well. The
/// envelope shell and the message shell are measured from their real
/// encodings; only the MessagePack length headers and base64 expansion that
/// grow with `ciphertext_len` are arithmetic.
pub fn frame_bytes_for_payload(ciphertext_len: usize) -> usize {
    let long = "x".repeat(MAX_IDENTITY_BYTES);
    let envelope_shell = wire_encode(&TransportEnvelope {
        schema_id: ENVELOPE_SCHEMA_ID.to_string(),
        caller_runtime_id: long.clone(),
        request_id: long.clone(),
        message_kind: EnvelopeKind::Invocation,
        nonce: [0xff; 12],
        ciphertext: Vec::new(),
    })
    .map_or(usize::MAX, |bytes| bytes.len());
    let message_shell = encode_cultnet_message_to_vec(
        &CultNetMessage::OperationResponse {
            message_id: long,
            service_id: CONNECTOR_SERVICE_ID.to_string(),
            operation: INVOKE_OPERATION.to_string(),
            status: OK_STATUS.to_string(),
            payload_schema: ENVELOPE_SCHEMA_ID.to_string(),
            payload_encoding: PAYLOAD_ENCODING.to_string(),
            payload: "A".to_string(),
            diagnostics: Vec::new(),
            source_runtime_id: None,
        },
        CultNetWireContract::CultNetSchemaV0,
    )
    .map_or(usize::MAX, |bytes| bytes.len());
    // The shell holds an empty `bin 8`: a marker and a zero length. The shell's
    // one-character payload takes a one-byte string header and the character.
    let envelope = envelope_shell
        .saturating_sub(2)
        .saturating_add(bin_header_bytes(ciphertext_len))
        .saturating_add(ciphertext_len);
    let payload = envelope.div_ceil(3).saturating_mul(4);
    message_shell
        .saturating_sub(2)
        .saturating_add(str_header_bytes(payload))
        .saturating_add(payload)
}

/// MessagePack `bin` header width for a byte string of `len` bytes.
fn bin_header_bytes(len: usize) -> usize {
    match len {
        0..=255 => 2,
        256..=65_535 => 3,
        _ => 5,
    }
}

/// MessagePack `str` header width for the base64 payload. The payload always
/// exceeds 255 bytes: the envelope it encodes holds two ids of at least
/// `MAX_IDENTITY_BYTES` in the worst case this bound measures.
fn str_header_bytes(len: usize) -> usize {
    if len <= 65_535 { 3 } else { 5 }
}

/// The largest payload bound whose worst-case frame fits `max_frame_bytes`:
/// the inverse of [`frame_bytes_for_payload`]. `None` when the frame cannot
/// carry even an empty envelope.
pub fn payload_bytes_for_frame(max_frame_bytes: usize) -> Option<usize> {
    if frame_bytes_for_payload(0) > max_frame_bytes {
        return None;
    }
    // A frame is longer than its payload, so the answer is below the bound.
    let (mut fits, mut over) = (0, max_frame_bytes.saturating_add(1));
    while over - fits > 1 {
        let middle = fits + (over - fits) / 2;
        if frame_bytes_for_payload(middle) <= max_frame_bytes {
            fits = middle;
        } else {
            over = middle;
        }
    }
    Some(fits)
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
        wire_decode(&plaintext).map_err(|_| ServiceError::Encoding)?;
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
    let plaintext = wire_encode(result).map_err(|_| ServiceError::Encoding)?;
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
    let result: TransportResult = wire_decode(&plaintext).map_err(|_| ServiceError::Encoding)?;
    if result.caller_runtime_id != envelope.caller_runtime_id
        || result.request_id != envelope.request_id
    {
        return Err(ServiceError::OuterIdentity);
    }
    result.validate_against(invocation)?;
    Ok(result)
}

/// A spend readout request carries no content: the sealed envelope's
/// authenticated identity and kind are the whole request.
pub(crate) fn encrypt_spend_readout_request(
    caller_runtime_id: &str,
    request_id: &str,
    security: &TransportKey,
) -> Result<TransportEnvelope, ServiceError> {
    encrypt_message(
        caller_runtime_id,
        request_id,
        EnvelopeKind::SpendReadoutRequest,
        &[],
        security,
    )
}

#[cfg(any(feature = "daemon", test))]
pub(crate) fn decrypt_spend_readout_request(
    envelope: &TransportEnvelope,
    security: &TransportKey,
) -> Result<(), ServiceError> {
    validate_envelope(envelope, EnvelopeKind::SpendReadoutRequest)?;
    decrypt_message(envelope, security).map(drop)
}

#[cfg(feature = "daemon")]
pub(crate) fn encrypt_spend_readout(
    caller_runtime_id: &str,
    request_id: &str,
    readout: &SpendReadout,
    security: &TransportKey,
) -> Result<TransportEnvelope, ServiceError> {
    let plaintext = wire_encode(readout).map_err(|_| ServiceError::Encoding)?;
    encrypt_message(
        caller_runtime_id,
        request_id,
        EnvelopeKind::SpendReadoutResult,
        &plaintext,
        security,
    )
}

pub(crate) fn decrypt_spend_readout(
    envelope: &TransportEnvelope,
    security: &TransportKey,
) -> Result<SpendReadout, ServiceError> {
    validate_envelope(envelope, EnvelopeKind::SpendReadoutResult)?;
    let plaintext = decrypt_message(envelope, security)?;
    let readout: SpendReadout = wire_decode(&plaintext).map_err(|_| ServiceError::Encoding)?;
    readout.validate()?;
    Ok(readout)
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

/// The authenticated data of a sealed message: a positional tuple, a MAC input
/// and not a wire document (a tuple is positional under the named codec too).
pub(crate) fn envelope_aad(
    schema_id: &str,
    caller_runtime_id: &str,
    request_id: &str,
    message_kind: EnvelopeKind,
) -> Result<Vec<u8>, ServiceError> {
    wire_encode(&(schema_id, caller_runtime_id, request_id, message_kind))
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
    #[error("an allowed model has no price: {0}")]
    UnpricedModel(String),
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
    #[error("transport encoding failed")]
    Encoding,
    #[error("frame is not a connector operation message")]
    Carriage,
    #[error("completion did not carry a transported provider outcome")]
    InvalidCompletion,
    #[error("completion has no active request")]
    NoActiveRequest,
    #[error("completion does not match the active request")]
    ActiveRequestMismatch,
    #[error("sealed result does not fit the frame bound")]
    FrameBound,
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
        let result = TransportResult::transported(Vec::new(), receipt(&invocation));
        let plaintext = wire_encode(&result).unwrap();
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
        schema.schema_id = concat!("gamecult.", "codex.transport_envelope.v2").to_string();
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

    /// The real result frame for an envelope with ids at the longest admitted
    /// and a ciphertext of `length` bytes.
    fn real_worst_frame(length: usize) -> Vec<u8> {
        let long = "x".repeat(MAX_IDENTITY_BYTES);
        encode_result_frame(&TransportEnvelope {
            schema_id: ENVELOPE_SCHEMA_ID.to_string(),
            caller_runtime_id: long.clone(),
            request_id: long,
            message_kind: EnvelopeKind::Invocation,
            nonce: [0xff; 12],
            ciphertext: vec![0xff; length],
        })
        .unwrap()
    }

    /// Ciphertext sizes either side of every length-header boundary the frame
    /// crosses: bin 8 to 16 to 32, str 8 to 16 to 32, and each base64 padding.
    fn boundary_sizes() -> Vec<usize> {
        let mut sizes: Vec<usize> = (0..=40).collect();
        for center in [
            100, 200, 250, 256, 300, 1000, 3000, 65_535, 65_536, 49_000, 49_100, 49_152, 49_200,
            70_000,
        ] {
            for delta in 0..=40 {
                sizes.push(center + delta);
                sizes.push(center.saturating_sub(delta));
            }
        }
        sizes.sort_unstable();
        sizes.dedup();
        sizes
    }

    #[test]
    fn the_frame_bound_is_the_real_carriage_encoding() {
        for length in boundary_sizes() {
            assert_eq!(
                real_worst_frame(length).len(),
                frame_bytes_for_payload(length),
                "{length}"
            );
        }
    }

    #[test]
    fn a_sealed_envelope_never_exceeds_the_worst_frame_for_its_ciphertext() {
        let key = security("epiphany-distinct-test-key");
        for id in ["a".to_string(), "i".repeat(MAX_IDENTITY_BYTES)] {
            for plaintext in [1, 100, 5_000, 70_000] {
                let sealed =
                    encrypt_message(&id, &id, EnvelopeKind::Result, &vec![0x41; plaintext], &key)
                        .unwrap();
                let worst = frame_bytes_for_payload(sealed.ciphertext.len());
                for real in [
                    encode_result_frame(&sealed).unwrap().len(),
                    encode_invocation_frame(&sealed).unwrap().len(),
                ] {
                    assert!(real <= worst, "{real} > {worst}");
                }
                // The frame is the base64 of the envelope: its worst case is
                // within the base64 expansion of the real one.
                if id.len() == MAX_IDENTITY_BYTES {
                    let real = encode_result_frame(&sealed).unwrap().len();
                    assert!(worst <= real + 32, "{worst} {real}");
                }
            }
        }
    }

    #[test]
    fn the_payload_bound_a_frame_allows_is_the_largest_payload_that_fits() {
        // The frame grows in base64 groups of three bytes, so several payloads
        // share a frame: the inverse is the largest of them.
        assert_eq!(
            payload_bytes_for_frame(frame_bytes_for_payload(0) - 1),
            None
        );
        for bytes in boundary_sizes().into_iter().chain([2_000_000]) {
            let frame = frame_bytes_for_payload(bytes);
            let allowed = payload_bytes_for_frame(frame).unwrap();
            assert!(allowed >= bytes && allowed - bytes < 3, "{bytes} {allowed}");
            assert_eq!(frame_bytes_for_payload(allowed), frame, "{bytes}");
            assert!(frame_bytes_for_payload(allowed + 1) > frame, "{bytes}");
            assert!(
                payload_bytes_for_frame(frame - 1).is_none_or(|smaller| smaller < bytes),
                "{bytes}"
            );
        }
    }

    #[test]
    fn ciphertext_travels_as_binary() {
        let key = security("epiphany-distinct-test-key");
        for plaintext in [10, 300, 70_000] {
            let sealed = encrypt_message(
                "caller",
                "request",
                EnvelopeKind::Invocation,
                &vec![0x41; plaintext],
                &key,
            )
            .unwrap();
            let length = sealed.ciphertext.len();
            let mut expected = match length {
                0..=255 => vec![0xc4, length as u8],
                256..=65_535 => [&[0xc5][..], &(length as u16).to_be_bytes()].concat(),
                _ => [&[0xc6][..], &(length as u32).to_be_bytes()].concat(),
            };
            expected.extend(&sealed.ciphertext);
            let encoded = wire_encode(&sealed).unwrap();
            assert!(
                encoded
                    .windows(expected.len())
                    .any(|window| window == expected),
                "{plaintext}"
            );
        }
    }

    fn sealed_for_carriage() -> TransportEnvelope {
        encrypt_invocation(&invocation(), &security("epiphany-distinct-test-key")).unwrap()
    }

    fn request_message(edit: impl FnOnce(&mut CultNetMessage)) -> Vec<u8> {
        let envelope = sealed_for_carriage();
        let mut message = decode_cultnet_message_from_slice(
            &encode_invocation_frame(&envelope).unwrap(),
            CultNetWireContract::CultNetSchemaV0,
        )
        .unwrap();
        edit(&mut message);
        carriage_bytes(&message).unwrap()
    }

    fn response_message(edit: impl FnOnce(&mut CultNetMessage)) -> Vec<u8> {
        let envelope = sealed_for_carriage();
        let mut message = decode_cultnet_message_from_slice(
            &encode_result_frame(&envelope).unwrap(),
            CultNetWireContract::CultNetSchemaV0,
        )
        .unwrap();
        edit(&mut message);
        carriage_bytes(&message).unwrap()
    }

    #[test]
    fn the_carriage_round_trips_both_directions() {
        let envelope = sealed_for_carriage();
        assert_eq!(
            decode_invocation_frame(&encode_invocation_frame(&envelope).unwrap()).unwrap(),
            envelope
        );
        assert_eq!(
            decode_result_frame(&encode_result_frame(&envelope).unwrap()).unwrap(),
            envelope
        );
        // A request is not a response, in either direction.
        assert_eq!(
            decode_result_frame(&encode_invocation_frame(&envelope).unwrap()),
            Err(ServiceError::Carriage)
        );
        assert_eq!(
            decode_invocation_frame(&encode_result_frame(&envelope).unwrap()),
            Err(ServiceError::Carriage)
        );
    }

    #[test]
    fn the_carriage_refuses_another_service_operation_or_schema() {
        fn edit_request(field: &str, value: &str) -> Vec<u8> {
            request_message(|message| {
                if let CultNetMessage::OperationRequest {
                    service_id,
                    operation,
                    payload_schema,
                    ..
                } = message
                {
                    match field {
                        "service" => *service_id = value.to_string(),
                        "operation" => *operation = value.to_string(),
                        _ => *payload_schema = value.to_string(),
                    }
                }
            })
        }
        fn edit_response(field: &str, value: &str) -> Vec<u8> {
            response_message(|message| {
                if let CultNetMessage::OperationResponse {
                    service_id,
                    operation,
                    payload_schema,
                    status,
                    ..
                } = message
                {
                    match field {
                        "service" => *service_id = value.to_string(),
                        "operation" => *operation = value.to_string(),
                        "status" => *status = value.to_string(),
                        _ => *payload_schema = value.to_string(),
                    }
                }
            })
        }
        for (field, value) in [
            ("service", "gamecult.model.other"),
            ("operation", "cancel"),
            ("schema", "gamecult.model.transport_envelope.v2"),
        ] {
            assert_eq!(
                decode_invocation_frame(&edit_request(field, value)),
                Err(ServiceError::Carriage),
                "{field}"
            );
            assert_eq!(
                decode_result_frame(&edit_response(field, value)),
                Err(ServiceError::Carriage),
                "{field}"
            );
        }
        assert_eq!(
            decode_result_frame(&edit_response("status", "rejected")),
            Err(ServiceError::Carriage)
        );
        // The unedited message decodes, so each refusal above is the edit's.
        assert!(decode_invocation_frame(&edit_request("service", CONNECTOR_SERVICE_ID)).is_ok());
        assert!(decode_result_frame(&edit_response("status", "ok")).is_ok());
    }

    #[test]
    fn the_carriage_refuses_a_message_id_that_is_not_the_envelopes_request_id() {
        let request = request_message(|message| {
            if let CultNetMessage::OperationRequest { message_id, .. } = message {
                *message_id = "another-request".to_string();
            }
        });
        let response = response_message(|message| {
            if let CultNetMessage::OperationResponse { message_id, .. } = message {
                *message_id = "another-request".to_string();
            }
        });
        assert_eq!(
            decode_invocation_frame(&request),
            Err(ServiceError::OuterIdentity)
        );
        assert_eq!(
            decode_result_frame(&response),
            Err(ServiceError::OuterIdentity)
        );
    }

    #[test]
    fn the_carriage_refuses_what_is_not_a_connector_message() {
        let good = encode_invocation_frame(&sealed_for_carriage()).unwrap();
        // Not MessagePack of any CultNet message, nor a truncated one.
        assert_eq!(
            decode_invocation_frame(&[0xc1, 0x00, 0x01]),
            Err(ServiceError::Carriage)
        );
        assert_eq!(
            decode_invocation_frame(&good[..good.len() / 2]),
            Err(ServiceError::Carriage)
        );
        // A payload that is not base64, and base64 of something else.
        let not_base64 = request_message(|message| {
            if let CultNetMessage::OperationRequest { payload, .. } = message {
                *payload = "!!not base64!!".to_string();
            }
        });
        assert_eq!(
            decode_invocation_frame(&not_base64),
            Err(ServiceError::Carriage)
        );
        let not_an_envelope = request_message(|message| {
            if let CultNetMessage::OperationRequest { payload, .. } = message {
                *payload = STANDARD.encode(b"\x01\x02");
            }
        });
        assert_eq!(
            decode_invocation_frame(&not_an_envelope),
            Err(ServiceError::Encoding)
        );
    }

    fn golden_frame() -> Vec<u8> {
        std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/wire_v3/carriage_invocation.frame"),
        )
        .expect("carriage_invocation.frame is committed")
    }

    #[test]
    fn the_committed_golden_frame_is_what_the_kit_reads_and_writes() {
        let frame = golden_frame();
        let envelope = decode_invocation_frame(&frame).unwrap();
        assert_eq!(encode_invocation_frame(&envelope).unwrap(), frame);
    }

    fn top_level(frame: &[u8]) -> std::collections::BTreeMap<String, rmpv::Value> {
        let rmpv::Value::Map(entries) = rmpv::decode::read_value(&mut &frame[..]).unwrap() else {
            panic!("a CultNet frame is a map");
        };
        entries
            .into_iter()
            .map(|(key, value)| (key.as_str().unwrap().to_string(), value))
            .collect()
    }

    #[test]
    fn the_frames_name_the_connector_service_and_its_one_operation_on_the_wire() {
        let envelope = sealed_for_carriage();
        let text = |map: &std::collections::BTreeMap<String, rmpv::Value>, key: &str| {
            map[key].as_str().unwrap().to_string()
        };
        let request = top_level(&encode_invocation_frame(&envelope).unwrap());
        assert_eq!(
            text(&request, "schemaVersion"),
            "cultnet.operation_request.v0"
        );
        assert_eq!(text(&request, "serviceId"), "gamecult.model.connector");
        assert_eq!(text(&request, "operation"), "invoke");
        assert_eq!(
            text(&request, "payloadSchema"),
            "gamecult.model.transport_envelope.v3"
        );
        assert_eq!(text(&request, "payloadEncoding"), "messagepack-base64");
        assert_eq!(text(&request, "messageId"), envelope.request_id);
        let response = top_level(&encode_result_frame(&envelope).unwrap());
        assert_eq!(
            text(&response, "schemaVersion"),
            "cultnet.operation_response.v0"
        );
        assert_eq!(text(&response, "serviceId"), "gamecult.model.connector");
        assert_eq!(text(&response, "operation"), "invoke");
        assert_eq!(text(&response, "status"), "ok");
        assert_eq!(
            text(&response, "payloadSchema"),
            "gamecult.model.transport_envelope.v3"
        );
        assert_eq!(text(&response, "payloadEncoding"), "messagepack-base64");
        assert_eq!(text(&response, "messageId"), envelope.request_id);
    }

    fn value_of(bytes: &[u8]) -> rmpv::Value {
        rmpv::decode::read_value(&mut &bytes[..]).unwrap()
    }

    fn bytes_of(value: &rmpv::Value) -> Vec<u8> {
        let mut out = Vec::new();
        rmpv::encode::write_value(&mut out, value).unwrap();
        out
    }

    fn with_entry(value: rmpv::Value, name: &str, entry: rmpv::Value) -> rmpv::Value {
        let rmpv::Value::Map(mut entries) = value else {
            panic!("a named document is a map");
        };
        let slot = entries
            .iter_mut()
            .find(|(key, _)| key.as_str() == Some(name))
            .unwrap();
        slot.1 = entry;
        rmpv::Value::Map(entries)
    }

    fn reverse_maps(value: rmpv::Value) -> rmpv::Value {
        match value {
            rmpv::Value::Map(entries) => rmpv::Value::Map(
                entries
                    .into_iter()
                    .rev()
                    .map(|(key, entry)| (key, reverse_maps(entry)))
                    .collect(),
            ),
            rmpv::Value::Array(items) => {
                rmpv::Value::Array(items.into_iter().map(reverse_maps).collect())
            }
            other => other,
        }
    }

    fn without_nils(value: rmpv::Value) -> rmpv::Value {
        match value {
            rmpv::Value::Map(entries) => rmpv::Value::Map(
                entries
                    .into_iter()
                    .filter(|(_, entry)| !entry.is_nil())
                    .map(|(key, entry)| (key, without_nils(entry)))
                    .collect(),
            ),
            rmpv::Value::Array(items) => {
                rmpv::Value::Array(items.into_iter().map(without_nils).collect())
            }
            other => other,
        }
    }

    fn request_frame_carrying(payload: &[u8]) -> Vec<u8> {
        request_message(|message| {
            if let CultNetMessage::OperationRequest { payload: sent, .. } = message {
                *sent = STANDARD.encode(payload);
            }
        })
    }

    fn response_frame_carrying(payload: &[u8]) -> Vec<u8> {
        response_message(|message| {
            if let CultNetMessage::OperationResponse { payload: sent, .. } = message {
                *sent = STANDARD.encode(payload);
            }
        })
    }

    #[test]
    fn the_carriage_refuses_every_dialect_the_wire_does_not_name() {
        let envelope = sealed_for_carriage();
        let named = value_of(&wire_encode(&envelope).unwrap());
        let integer_ciphertext = rmpv::Value::Array(
            envelope
                .ciphertext
                .iter()
                .map(|byte| rmpv::Value::from(*byte))
                .collect(),
        );
        let dialects = [
            ("positional envelope", rmp_serde::to_vec(&envelope).unwrap()),
            (
                "integer-array ciphertext",
                bytes_of(&with_entry(named.clone(), "ciphertext", integer_ciphertext)),
            ),
            (
                "enum as its index",
                bytes_of(&with_entry(named, "message_kind", 0.into())),
            ),
            (
                "bytes after the document",
                [wire_encode(&envelope).unwrap(), vec![0xc0]].concat(),
            ),
        ];
        for (dialect, payload) in &dialects {
            assert_eq!(
                decode_invocation_frame(&request_frame_carrying(payload)),
                Err(ServiceError::Encoding),
                "{dialect} on a request"
            );
            assert_eq!(
                decode_result_frame(&response_frame_carrying(payload)),
                Err(ServiceError::Encoding),
                "{dialect} on a response"
            );
        }
        // The named form itself is read, so the refusals above are the dialect's.
        let named_bytes = wire_encode(&envelope).unwrap();
        assert_eq!(
            decode_invocation_frame(&request_frame_carrying(&named_bytes)),
            Ok(envelope)
        );
    }

    #[test]
    fn a_sealed_positional_invocation_is_refused_after_decryption() {
        let key = security("epiphany-distinct-test-key");
        let invocation = invocation();
        let sealed = encrypt_message(
            &invocation.caller_runtime_id,
            invocation.request_id(),
            EnvelopeKind::Invocation,
            &rmp_serde::to_vec(&invocation).unwrap(),
            &key,
        )
        .unwrap();
        let arrived = decode_invocation_frame(&encode_invocation_frame(&sealed).unwrap()).unwrap();
        assert_eq!(
            decrypt_invocation(&arrived, &key),
            Err(ServiceError::Encoding)
        );
        let sealed = encrypt_invocation(&invocation, &key).unwrap();
        assert_eq!(decrypt_invocation(&sealed, &key), Ok(invocation));
    }

    #[test]
    fn named_maps_in_any_key_order_and_without_absent_options_are_the_named_form() {
        let envelope = sealed_for_carriage();
        let reversed = bytes_of(&reverse_maps(value_of(&wire_encode(&envelope).unwrap())));
        assert_ne!(reversed, wire_encode(&envelope).unwrap());
        assert_eq!(wire_decode::<TransportEnvelope>(&reversed), Ok(envelope));
        let invocation = invocation();
        let named = value_of(&wire_encode(&invocation).unwrap());
        for edited in [reverse_maps(named.clone()), without_nils(named)] {
            let bytes = bytes_of(&edited);
            assert_ne!(bytes, wire_encode(&invocation).unwrap());
            assert_eq!(
                wire_decode::<TransportInvocation>(&bytes),
                Ok(invocation.clone())
            );
        }
    }

    #[test]
    fn a_readout_request_is_not_an_invocation_and_names_its_own_operation() {
        let key = TransportKey::from_connection_secret("readout-test-key").unwrap();
        let sealed = encrypt_spend_readout_request("caller-1", "readout-1", &key).unwrap();
        let frame = encode_spend_readout_request_frame(&sealed).unwrap();
        assert!(matches!(
            decode_request_frame(&frame),
            Ok(RequestFrame::SpendReadout(found)) if found == sealed
        ));
        assert_eq!(decode_invocation_frame(&frame), Err(ServiceError::Carriage));
        // Sealed as one kind, the authenticated data refuses it as another.
        assert!(decrypt_spend_readout_request(&sealed, &key).is_ok());
        assert_eq!(
            decrypt_spend_readout(&sealed, &key).unwrap_err(),
            ServiceError::Envelope
        );
        let mut relabelled = sealed.clone();
        relabelled.message_kind = EnvelopeKind::SpendReadoutResult;
        assert_eq!(
            decrypt_spend_readout(&relabelled, &key).unwrap_err(),
            ServiceError::Encryption
        );
    }
}
