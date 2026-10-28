use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use thiserror::Error;
use zeroize::Zeroizing;

use crate::contract::{TransportInvocation, TransportKey, TransportResult};
use crate::envelope::{
    ServiceError, TransportFrameError, decrypt_result, encrypt_invocation, read_transport_frame,
    write_transport_frame,
};

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
        let request = rmp_serde::to_vec(&encrypt_invocation(invocation, &self.security)?)
            .map_err(|_| ConnectorClientError::Encoding)?;
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
        write_transport_frame(&mut stream, &request, self.max_frame_bytes)
            .map_err(client_frame_error)?;
        let response =
            read_transport_frame(&mut stream, self.max_frame_bytes).map_err(client_frame_error)?;
        let envelope =
            rmp_serde::from_slice(&response).map_err(|_| ConnectorClientError::Encoding)?;
        decrypt_result(&envelope, &self.security, invocation).map_err(Into::into)
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
    #[error("connector MessagePack encoding failed")]
    Encoding,
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
            let envelope: TransportEnvelope = rmp_serde::from_slice(&request).unwrap();
            assert_eq!(decrypt_invocation(&envelope, &security).unwrap(), expected);
            let response = encrypt_result(
                &TransportResult::refused(&expected, Refusal::Policy),
                &security,
            )
            .unwrap();
            write_transport_frame(
                &mut stream,
                &rmp_serde::to_vec(&response).unwrap(),
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
            TransportDisposition::Refused(Refusal::Policy)
        );
        server.join().unwrap();
    }
}
