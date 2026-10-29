use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use thiserror::Error;
use zeroize::Zeroizing;

use rand_core::{OsRng, RngCore};

use crate::contract::{TransportInvocation, TransportKey, TransportResult};
use crate::envelope::{
    MAX_IDENTITY_BYTES, ServiceError, TransportFrameError, decode_result_frame,
    decode_spend_readout_response_frame, decrypt_result, decrypt_spend_readout,
    encode_invocation_frame, encode_spend_readout_request_frame, encrypt_invocation,
    encrypt_spend_readout_request, read_transport_frame, write_transport_frame,
};
use crate::readout::SpendReadout;

#[derive(Clone)]
pub struct ConnectorClient {
    endpoint: SocketAddr,
    security: TransportKey,
    max_frame_bytes: usize,
    response_timeout: Option<Duration>,
}

impl ConnectorClient {
    pub fn new(
        endpoint: SocketAddr,
        connection_key: impl Into<String>,
        max_frame_bytes: usize,
        response_timeout: Option<Duration>,
    ) -> Result<Self, ConnectorClientError> {
        if endpoint.port() == 0
            || endpoint.ip().is_unspecified()
            || endpoint.ip().is_multicast()
            || endpoint.ip() == std::net::Ipv4Addr::BROADCAST
            || !(4096..=u32::MAX as usize).contains(&max_frame_bytes)
            || response_timeout.is_some_and(|timeout| timeout.is_zero())
        {
            return Err(ConnectorClientError::InvalidConfig);
        }
        let connection_key = Zeroizing::new(connection_key.into());
        let security = TransportKey::from_connection_secret(connection_key.as_str())?;
        Ok(Self {
            endpoint,
            security,
            max_frame_bytes,
            response_timeout,
        })
    }

    pub fn execute(
        &self,
        invocation: &TransportInvocation,
    ) -> Result<TransportResult, ConnectorClientError> {
        if invocation.request_id().len() > MAX_IDENTITY_BYTES {
            return Err(ConnectorClientError::RequestIdTooLong);
        }
        let request = encode_invocation_frame(&encrypt_invocation(invocation, &self.security)?)?;
        let response = self.exchange(&request)?;
        let envelope = decode_result_frame(&response)?;
        decrypt_result(&envelope, &self.security, invocation).map_err(Into::into)
    }

    /// Reads the connector's spend ledger and plan quota as `caller_runtime_id`,
    /// which must be a caller whose connection key this client holds.
    pub fn spend_readout(
        &self,
        caller_runtime_id: &str,
    ) -> Result<SpendReadout, ConnectorClientError> {
        let mut nonce = [0_u8; 16];
        OsRng.fill_bytes(&mut nonce);
        let request_id = format!(
            "spend-readout-{}",
            nonce.iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
        let sealed = encrypt_spend_readout_request(caller_runtime_id, &request_id, &self.security)?;
        let response = self.exchange(&encode_spend_readout_request_frame(&sealed)?)?;
        let envelope = decode_spend_readout_response_frame(&response)?;
        if envelope.caller_runtime_id != caller_runtime_id || envelope.request_id != request_id {
            return Err(ServiceError::OuterIdentity.into());
        }
        decrypt_spend_readout(&envelope, &self.security).map_err(Into::into)
    }

    /// Sends one frame on a fresh connection and reads the one answer.
    fn exchange(&self, request: &[u8]) -> Result<Vec<u8>, ConnectorClientError> {
        let connect_timeout = self
            .response_timeout
            .unwrap_or(Duration::from_secs(10))
            .min(Duration::from_secs(10));
        let mut stream = TcpStream::connect_timeout(&self.endpoint, connect_timeout)
            .map_err(ConnectorClientError::Connection)?;
        stream
            .set_read_timeout(self.response_timeout)
            .and_then(|()| stream.set_write_timeout(self.response_timeout))
            .map_err(ConnectorClientError::Connection)?;
        write_transport_frame(&mut stream, request, self.max_frame_bytes)
            .map_err(client_frame_error)?;
        read_transport_frame(&mut stream, self.max_frame_bytes).map_err(client_frame_error)
    }
}

#[cfg(test)]
mod client_endpoint_tests {
    use super::*;

    #[test]
    fn client_admits_explicit_unicast_and_refuses_non_destinations() {
        for endpoint in ["127.0.0.1:4103", "172.19.0.1:4103", "[::1]:4103"] {
            assert!(
                ConnectorClient::new(
                    endpoint.parse().unwrap(),
                    "bounded-client-endpoint-key",
                    64 * 1024,
                    Some(Duration::from_secs(1)),
                )
                .is_ok(),
                "{endpoint} should be an admissible explicit destination"
            );
        }
        for endpoint in [
            "0.0.0.0:4103",
            "255.255.255.255:4103",
            "224.0.0.1:4103",
            "[::]:4103",
            "[ff02::1]:4103",
            "127.0.0.1:0",
        ] {
            assert!(matches!(
                ConnectorClient::new(
                    endpoint.parse().unwrap(),
                    "bounded-client-endpoint-key",
                    64 * 1024,
                    Some(Duration::from_secs(1)),
                ),
                Err(ConnectorClientError::InvalidConfig)
            ));
        }
    }
}

#[derive(Debug, Error)]
pub enum ConnectorClientError {
    #[error("invalid connector client configuration")]
    InvalidConfig,
    #[error("connector client connection failed")]
    Connection(#[source] std::io::Error),
    #[error("connector frame exceeded its bound")]
    FrameSize,
    #[error("request id is longer than the connector identity bound")]
    RequestIdTooLong,
    #[error(transparent)]
    Transport(#[from] ServiceError),
}

fn client_frame_error(error: TransportFrameError) -> ConnectorClientError {
    match error {
        TransportFrameError::Connection(error) => ConnectorClientError::Connection(error),
        TransportFrameError::Size => ConnectorClientError::FrameSize,
    }
}

#[cfg(test)]
mod fixture_tests {
    use super::*;
    use crate::fixtures::*;
    use crate::{contract::*, envelope::*};

    #[test]
    fn shared_client_transports_one_exact_encrypted_request_and_result() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let invocation = invocation();
        let expected = invocation.clone();
        let security = security("epiphany-distinct-test-key");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_transport_frame(&mut stream, 64 * 1024).unwrap();
            let envelope = decode_invocation_frame(&request).unwrap();
            assert_eq!(decrypt_invocation(&envelope, &security).unwrap(), expected);
            let response = encrypt_result(
                &TransportResult::refused(&expected, Refusal::ModelNotAllowed),
                &security,
            )
            .unwrap();
            write_transport_frame(
                &mut stream,
                &encode_result_frame(&response).unwrap(),
                64 * 1024,
            )
            .unwrap();
        });

        let client = ConnectorClient::new(
            endpoint,
            "epiphany-distinct-test-key",
            64 * 1024,
            Some(Duration::from_secs(1)),
        )
        .unwrap();
        assert_eq!(
            client.execute(&invocation).unwrap().disposition,
            TransportDisposition::Refused(Refusal::ModelNotAllowed)
        );
        server.join().unwrap();
    }

    #[test]
    fn an_over_long_request_id_is_refused_locally_before_any_byte_is_sent() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let client = ConnectorClient::new(
            listener.local_addr().unwrap(),
            "epiphany-distinct-test-key",
            64 * 1024,
            Some(Duration::from_secs(1)),
        )
        .unwrap();
        let mut long = invocation();
        long.request.request_id = "r".repeat(MAX_IDENTITY_BYTES + 1);
        assert!(matches!(
            client.execute(&long),
            Err(ConnectorClientError::RequestIdTooLong)
        ));
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "the client must not even connect"
        );
    }

    #[test]
    fn the_client_measures_a_request_id_in_bytes() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let client = ConnectorClient::new(
            listener.local_addr().unwrap(),
            "epiphany-distinct-test-key",
            64 * 1024,
            Some(Duration::from_secs(1)),
        )
        .unwrap();
        // 86 characters, 258 bytes: under the bound by characters, over by bytes.
        let id = "\u{20AC}".repeat(86);
        assert_eq!((id.chars().count(), id.len()), (86, 258));
        let mut long = invocation();
        long.request.request_id = id;
        assert!(matches!(
            client.execute(&long),
            Err(ConnectorClientError::RequestIdTooLong)
        ));
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "the client must not even connect"
        );
    }

    #[cfg(feature = "daemon")]
    #[test]
    fn a_readout_is_accepted_only_for_the_identity_that_asked() {
        use crate::readout::PlanQuotaSnapshot;
        // (caller the answer is sealed for, request id override, accepted)
        let cases = [
            ("caller-1", None, true),
            ("caller-2", None, false),
            ("caller-1", Some("some-other-request"), false),
        ];
        for (answer_caller, answer_request, accepted) in cases {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let endpoint = listener.local_addr().unwrap();
            let key = security("readout-client-key");
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let request = read_transport_frame(&mut stream, 64 * 1024).unwrap();
                let RequestFrame::SpendReadout(asked) = decode_request_frame(&request).unwrap()
                else {
                    panic!("the client sent something other than a readout request");
                };
                let request_id = answer_request.unwrap_or(&asked.request_id);
                let readout = SpendReadout::new(1, Vec::new(), PlanQuotaSnapshot::default());
                let sealed =
                    encrypt_spend_readout(answer_caller, request_id, &readout, &key).unwrap();
                write_transport_frame(
                    &mut stream,
                    &encode_spend_readout_response_frame(&sealed).unwrap(),
                    64 * 1024,
                )
                .unwrap();
            });
            let client = ConnectorClient::new(
                endpoint,
                "readout-client-key",
                64 * 1024,
                Some(Duration::from_secs(1)),
            )
            .unwrap();
            let answer = client.spend_readout("caller-1");
            if accepted {
                assert_eq!(answer.unwrap().at_unix_ms, 1);
            } else {
                assert!(matches!(
                    answer,
                    Err(ConnectorClientError::Transport(ServiceError::OuterIdentity))
                ));
            }
            server.join().unwrap();
        }
    }
}
