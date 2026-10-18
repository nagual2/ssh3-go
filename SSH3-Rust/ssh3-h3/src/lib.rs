use std::{fmt, io::Cursor, sync::Arc};

use bytes::Bytes;
use h3::ext::Protocol;
use http::{
    HeaderValue, Method, Request, Response, StatusCode, Uri,
    header::{SERVER, USER_AGENT},
};
use ssh3_core::{Conversation, ConversationError, ConversationId};
use ssh3_proto::read_var_int;
use ssh3_quinn::{IncomingChannelRouter, QuinnDatagramSender, RouteAcceptedChannelError};

pub const SSH3_PROTOCOL_NAME: &str = "ssh3";
pub const SSH3_EXPORTER_LABEL: &[u8] = b"EXPORTER-SSH3";
pub const SSH3_CONVERSATION_ID_LEN: usize = 32;
pub const SSH3_USER_HEADER: &str = "x-ssh3-user";
pub const SSH3_VERSION_STRING: &str = "SSH 3.0 ssh3-rust 0.1.0 experimental_spec_version=alpha-00";

pub type QuinnConnection = h3_quinn::Connection;
pub type ClientConnection = h3::client::Connection<QuinnConnection, Bytes>;
pub type ServerConnection = h3::server::Connection<QuinnConnection, Bytes>;
pub type SendRequest = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;
pub type ClientControlStream = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
pub type ServerControlStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

#[derive(Debug)]
pub enum BuildConnectRequestError {
    InvalidUserAgent(http::header::InvalidHeaderValue),
    Http(http::Error),
}

impl fmt::Display for BuildConnectRequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUserAgent(err) => write!(f, "{err}"),
            Self::Http(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for BuildConnectRequestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidUserAgent(err) => Some(err),
            Self::Http(err) => Some(err),
        }
    }
}

impl From<http::header::InvalidHeaderValue> for BuildConnectRequestError {
    fn from(value: http::header::InvalidHeaderValue) -> Self {
        Self::InvalidUserAgent(value)
    }
}

impl From<http::Error> for BuildConnectRequestError {
    fn from(value: http::Error) -> Self {
        Self::Http(value)
    }
}

#[derive(Debug)]
pub struct ConversationIdError {
    inner: h3_quinn::quinn::crypto::ExportKeyingMaterialError,
}

impl fmt::Display for ConversationIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "failed to export conversation keying material: {:?}",
            self.inner
        )
    }
}

impl std::error::Error for ConversationIdError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl From<h3_quinn::quinn::crypto::ExportKeyingMaterialError> for ConversationIdError {
    fn from(value: h3_quinn::quinn::crypto::ExportKeyingMaterialError) -> Self {
        Self { inner: value }
    }
}

#[derive(Debug)]
pub enum ClientConversationError {
    ConversationId(ConversationIdError),
    Stream(h3::error::StreamError),
    UnexpectedStatus { status: StatusCode },
}

impl fmt::Display for ClientConversationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConversationId(err) => write!(f, "{err}"),
            Self::Stream(err) => write!(f, "{err}"),
            Self::UnexpectedStatus { status } => write!(f, "unexpected HTTP status: {status}"),
        }
    }
}

impl std::error::Error for ClientConversationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ConversationId(err) => Some(err),
            Self::Stream(err) => Some(err),
            Self::UnexpectedStatus { .. } => None,
        }
    }
}

impl From<ConversationIdError> for ClientConversationError {
    fn from(value: ConversationIdError) -> Self {
        Self::ConversationId(value)
    }
}

impl From<h3::error::StreamError> for ClientConversationError {
    fn from(value: h3::error::StreamError) -> Self {
        Self::Stream(value)
    }
}

#[derive(Debug)]
pub enum ServerConversationError {
    Connection(h3::error::ConnectionError),
    Stream(h3::error::StreamError),
    ConversationId(ConversationIdError),
}

impl fmt::Display for ServerConversationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connection(err) => write!(f, "{err}"),
            Self::Stream(err) => write!(f, "{err}"),
            Self::ConversationId(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for ServerConversationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Connection(err) => Some(err),
            Self::Stream(err) => Some(err),
            Self::ConversationId(err) => Some(err),
        }
    }
}

impl From<h3::error::ConnectionError> for ServerConversationError {
    fn from(value: h3::error::ConnectionError) -> Self {
        Self::Connection(value)
    }
}

impl From<h3::error::StreamError> for ServerConversationError {
    fn from(value: h3::error::StreamError) -> Self {
        Self::Stream(value)
    }
}

impl From<ConversationIdError> for ServerConversationError {
    fn from(value: ConversationIdError) -> Self {
        Self::ConversationId(value)
    }
}

#[derive(Debug)]
pub enum DatagramDispatchError {
    Connection(h3_quinn::quinn::ConnectionError),
    Proto(ssh3_proto::Error),
    Conversation(ConversationError),
}

impl fmt::Display for DatagramDispatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connection(err) => write!(f, "{err}"),
            Self::Proto(err) => write!(f, "{err}"),
            Self::Conversation(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for DatagramDispatchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Connection(err) => Some(err),
            Self::Proto(err) => Some(err),
            Self::Conversation(err) => Some(err),
        }
    }
}

impl From<h3_quinn::quinn::ConnectionError> for DatagramDispatchError {
    fn from(value: h3_quinn::quinn::ConnectionError) -> Self {
        Self::Connection(value)
    }
}

impl From<ssh3_proto::Error> for DatagramDispatchError {
    fn from(value: ssh3_proto::Error) -> Self {
        Self::Proto(value)
    }
}

impl From<ConversationError> for DatagramDispatchError {
    fn from(value: ConversationError) -> Self {
        Self::Conversation(value)
    }
}

pub struct EstablishedClientConversation {
    pub conversation: Arc<Conversation>,
    pub connection: h3_quinn::quinn::Connection,
    pub control_stream: ClientControlStream,
    pub response: Response<()>,
}

pub struct AcceptedServerConversation {
    pub conversation: Arc<Conversation>,
    pub connection: h3_quinn::quinn::Connection,
    pub control_stream: ServerControlStream,
    pub request: Request<()>,
}

pub struct ServerConnectionDriver {
    connection: h3_quinn::quinn::Connection,
    server: ServerConnection,
    channel_router: Arc<IncomingChannelRouter>,
}

impl ServerConnectionDriver {
    pub async fn new(
        connection: h3_quinn::quinn::Connection,
    ) -> Result<Self, h3::error::ConnectionError> {
        let server = new_server(connection.clone()).await?;
        Ok(Self {
            connection,
            server,
            channel_router: Arc::new(IncomingChannelRouter::new()),
        })
    }

    pub fn connection(&self) -> &h3_quinn::quinn::Connection {
        &self.connection
    }

    pub fn channel_router(&self) -> &Arc<IncomingChannelRouter> {
        &self.channel_router
    }

    pub async fn accept_conversation(
        &mut self,
        max_packet_size: u64,
        default_datagrams_queue_size: usize,
    ) -> Result<Option<AcceptedServerConversation>, ServerConversationError> {
        let accepted = accept_server_conversation(
            &mut self.server,
            self.connection.clone(),
            max_packet_size,
            default_datagrams_queue_size,
        )
        .await?;
        if let Some(conversation) = accepted
            .as_ref()
            .map(|accepted| accepted.conversation.clone())
        {
            self.channel_router.register_conversation(conversation);
        }
        Ok(accepted)
    }

    pub fn unregister_conversation(&self, control_stream_id: u64) -> Option<Arc<Conversation>> {
        self.channel_router
            .unregister_conversation(control_stream_id)
    }

    pub async fn route_datagram(
        &self,
        datagram: &[u8],
    ) -> Result<Option<Arc<Conversation>>, DatagramDispatchError> {
        route_registered_datagram(self.channel_router.as_ref(), datagram).await
    }

    pub async fn accept_and_route_datagram(
        &self,
    ) -> Result<Option<Arc<Conversation>>, DatagramDispatchError> {
        let datagram = self.connection.read_datagram().await?;
        self.route_datagram(&datagram).await
    }

    pub async fn accept_and_route_datagrams_forever(&self) -> Result<(), DatagramDispatchError> {
        loop {
            self.accept_and_route_datagram().await?;
        }
    }

    pub async fn accept_and_route_channel(
        &self,
    ) -> Result<Arc<Conversation>, RouteAcceptedChannelError> {
        self.channel_router
            .accept_and_route_channel(&self.connection)
            .await
    }

    pub async fn accept_and_route_channels_forever(&self) -> Result<(), RouteAcceptedChannelError> {
        self.channel_router
            .clone()
            .accept_and_route_channels_forever(self.connection.clone())
            .await
    }
}

pub fn ssh3_protocol() -> Protocol {
    Protocol::new(SSH3_PROTOCOL_NAME)
}

pub fn configure_client_builder(builder: &mut h3::client::Builder) -> &mut h3::client::Builder {
    builder.enable_extended_connect(true).enable_datagram(true)
}

pub fn configure_server_builder(builder: &mut h3::server::Builder) -> &mut h3::server::Builder {
    builder.enable_extended_connect(true).enable_datagram(true)
}

pub async fn new_client(
    connection: h3_quinn::quinn::Connection,
) -> Result<(ClientConnection, SendRequest), h3::error::ConnectionError> {
    let mut builder = h3::client::builder();
    configure_client_builder(&mut builder);
    builder.build(QuinnConnection::new(connection)).await
}

pub async fn new_server(
    connection: h3_quinn::quinn::Connection,
) -> Result<ServerConnection, h3::error::ConnectionError> {
    let mut builder = h3::server::builder();
    configure_server_builder(&mut builder);
    builder.build(QuinnConnection::new(connection)).await
}

pub fn build_connect_request(
    uri: Uri,
    user_agent: impl AsRef<str>,
) -> Result<Request<()>, BuildConnectRequestError> {
    let mut request = Request::builder()
        .method(Method::CONNECT)
        .uri(uri)
        .body(())?;
    request
        .headers_mut()
        .insert(USER_AGENT, HeaderValue::from_str(user_agent.as_ref())?);
    request.extensions_mut().insert(ssh3_protocol());
    Ok(request)
}

pub fn generate_conversation_id(
    connection: &h3_quinn::quinn::Connection,
) -> Result<ConversationId, ConversationIdError> {
    let mut conversation_id = [0; SSH3_CONVERSATION_ID_LEN];
    connection.export_keying_material(&mut conversation_id, SSH3_EXPORTER_LABEL, &[])?;
    Ok(conversation_id)
}

pub async fn establish_client_conversation(
    send_request: &mut SendRequest,
    connection: h3_quinn::quinn::Connection,
    request: Request<()>,
    max_packet_size: u64,
    default_datagrams_queue_size: usize,
) -> Result<EstablishedClientConversation, ClientConversationError> {
    let conversation_id = generate_conversation_id(&connection)?;
    let mut control_stream = send_request.send_request(request).await?;
    let response = control_stream.recv_response().await?;
    if response.status() != StatusCode::OK {
        return Err(ClientConversationError::UnexpectedStatus {
            status: response.status(),
        });
    }

    let conversation = Arc::new(Conversation::new(
        control_stream.id().into_inner(),
        conversation_id,
        max_packet_size,
        default_datagrams_queue_size,
        Arc::new(QuinnDatagramSender::new(connection.clone())),
    ));

    Ok(EstablishedClientConversation {
        conversation,
        connection,
        control_stream,
        response,
    })
}

pub async fn accept_server_conversation(
    server: &mut ServerConnection,
    connection: h3_quinn::quinn::Connection,
    max_packet_size: u64,
    default_datagrams_queue_size: usize,
) -> Result<Option<AcceptedServerConversation>, ServerConversationError> {
    let Some(resolver) = server.accept().await? else {
        return Ok(None);
    };
    let (request, control_stream) = resolver.resolve_request().await?;
    let conversation_id = generate_conversation_id(&connection)?;
    let conversation = Arc::new(Conversation::new(
        control_stream.id().into_inner(),
        conversation_id,
        max_packet_size,
        default_datagrams_queue_size,
        Arc::new(QuinnDatagramSender::new(connection.clone())),
    ));

    Ok(Some(AcceptedServerConversation {
        conversation,
        connection,
        control_stream,
        request,
    }))
}

pub fn request_protocol(request: &Request<()>) -> Option<&Protocol> {
    request.extensions().get::<Protocol>()
}

pub fn is_ssh3_connect(request: &Request<()>) -> bool {
    request.method() == Method::CONNECT
        && request_protocol(request).is_some_and(|protocol| protocol.as_str() == SSH3_PROTOCOL_NAME)
}

pub fn response_server_header(response: &Response<()>) -> Option<&str> {
    response
        .headers()
        .get(SERVER)
        .and_then(|value| value.to_str().ok())
}

pub fn request_user_agent(request: &Request<()>) -> Option<&str> {
    request
        .headers()
        .get(USER_AGENT)
        .and_then(|value| value.to_str().ok())
}

pub fn response_with_server_header(
    status: StatusCode,
    server_version: impl AsRef<str>,
) -> Result<Response<()>, BuildConnectRequestError> {
    Ok(Response::builder()
        .status(status)
        .header(SERVER, HeaderValue::from_str(server_version.as_ref())?)
        .body(())?)
}

pub async fn dispatch_datagram(
    conversation: &Conversation,
    datagram: &[u8],
) -> Result<(), DatagramDispatchError> {
    let mut cursor = Cursor::new(datagram);
    let control_stream_id = read_var_int(&mut cursor)?;
    if control_stream_id != conversation.control_stream_id() {
        return Ok(());
    }

    let offset = cursor.position() as usize;
    match conversation.add_datagram(&datagram[offset..]).await {
        Ok(()) | Err(ConversationError::ChannelNotFound { .. }) => Ok(()),
        Err(err) => Err(DatagramDispatchError::Conversation(err)),
    }
}

pub async fn route_registered_datagram(
    channel_router: &IncomingChannelRouter,
    datagram: &[u8],
) -> Result<Option<Arc<Conversation>>, DatagramDispatchError> {
    let mut cursor = Cursor::new(datagram);
    let control_stream_id = read_var_int(&mut cursor)?;
    let Some(conversation) = channel_router.conversation(control_stream_id) else {
        return Ok(None);
    };

    let offset = cursor.position() as usize;
    match conversation.add_datagram(&datagram[offset..]).await {
        Ok(()) | Err(ConversationError::ChannelNotFound { .. }) => Ok(Some(conversation)),
        Err(err) => Err(DatagramDispatchError::Conversation(err)),
    }
}

pub async fn dispatch_one_datagram(
    conversation: &Conversation,
    connection: &h3_quinn::quinn::Connection,
) -> Result<(), DatagramDispatchError> {
    let datagram = connection.read_datagram().await?;
    dispatch_datagram(conversation, &datagram).await
}

pub async fn dispatch_datagrams_forever(
    conversation: Arc<Conversation>,
    connection: h3_quinn::quinn::Connection,
) -> Result<(), DatagramDispatchError> {
    loop {
        dispatch_one_datagram(conversation.as_ref(), &connection).await?;
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::time::Duration;

    use futures_util::future;
    use http::{StatusCode, Version};
    use ssh3_core::AcceptedChannel;
    use ssh3_quinn::{
        client_config_for_certificate, open_udp_forwarding_channel, self_signed_server_config,
    };
    use tokio::sync::oneshot;

    use super::{
        SSH3_PROTOCOL_NAME, SSH3_VERSION_STRING, ServerConnectionDriver,
        accept_server_conversation, build_connect_request, establish_client_conversation,
        is_ssh3_connect, new_client, new_server, request_protocol, request_user_agent,
        response_server_header, response_with_server_header,
    };

    #[test]
    fn build_connect_request_sets_ssh3_protocol_and_user_agent() {
        let request = build_connect_request(
            "https://localhost/ssh3-term".parse().unwrap(),
            SSH3_VERSION_STRING,
        )
        .unwrap();

        assert_eq!(request.method(), http::Method::CONNECT);
        assert_eq!(
            request_protocol(&request).map(|protocol| protocol.as_str()),
            Some(SSH3_PROTOCOL_NAME)
        );
        assert_eq!(request_user_agent(&request), Some(SSH3_VERSION_STRING));
    }

    #[tokio::test]
    async fn bootstrap_creates_matching_client_and_server_conversations() {
        let (server_config, server_certificate) =
            self_signed_server_config(vec!["localhost".to_string()]).unwrap();
        let server_endpoint = h3_quinn::quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let mut client_endpoint = h3_quinn::quinn::Endpoint::client(SocketAddr::V4(
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        ))
        .unwrap();
        client_endpoint
            .set_default_client_config(client_config_for_certificate(server_certificate).unwrap());

        let client_connecting = client_endpoint.connect(server_addr, "localhost").unwrap();
        let (client_quinn, server_quinn) =
            tokio::join!(async { client_connecting.await.unwrap() }, async {
                let incoming = server_endpoint.accept().await.unwrap();
                incoming.await.unwrap()
            },);
        let (server_info_tx, server_info_rx) = oneshot::channel();
        let (response_seen_tx, response_seen_rx) = oneshot::channel();

        let server_task = tokio::spawn(async move {
            let mut server = new_server(server_quinn.clone()).await.unwrap();
            let mut accepted = tokio::time::timeout(
                Duration::from_secs(5),
                accept_server_conversation(&mut server, server_quinn, 30_000, 10),
            )
            .await
            .unwrap()
            .unwrap()
            .unwrap();

            assert!(is_ssh3_connect(&accepted.request));
            assert_eq!(accepted.request.version(), Version::HTTP_3);
            assert_eq!(
                request_user_agent(&accepted.request),
                Some(SSH3_VERSION_STRING)
            );
            assert_eq!(
                request_protocol(&accepted.request).map(|protocol| protocol.as_str()),
                Some(SSH3_PROTOCOL_NAME)
            );
            let _ = server_info_tx.send((
                accepted.conversation.conversation_id(),
                accepted.conversation.control_stream_id(),
            ));

            accepted
                .control_stream
                .send_response(
                    response_with_server_header(StatusCode::OK, SSH3_VERSION_STRING).unwrap(),
                )
                .await
                .unwrap();
            let _ = tokio::time::timeout(Duration::from_secs(5), response_seen_rx).await;
        });

        let client_task = tokio::spawn(async move {
            let client_quinn_for_close = client_quinn.clone();
            let (mut driver, mut send_request) = new_client(client_quinn.clone()).await.unwrap();
            let driver_task =
                tokio::spawn(async move { future::poll_fn(|cx| driver.poll_close(cx)).await });

            let established = tokio::time::timeout(
                Duration::from_secs(5),
                establish_client_conversation(
                    &mut send_request,
                    client_quinn,
                    build_connect_request(
                        "https://localhost/ssh3-term?user=tester".parse().unwrap(),
                        SSH3_VERSION_STRING,
                    )
                    .unwrap(),
                    30_000,
                    10,
                ),
            )
            .await
            .unwrap()
            .unwrap();

            let (server_conversation_id, server_control_stream_id) = server_info_rx.await.unwrap();
            assert_eq!(
                established.conversation.conversation_id(),
                server_conversation_id
            );
            assert_eq!(
                established.conversation.control_stream_id(),
                server_control_stream_id
            );
            assert_eq!(
                response_server_header(&established.response),
                Some(SSH3_VERSION_STRING)
            );

            let _ = response_seen_tx.send(());
            client_quinn_for_close.close(0u32.into(), b"done");
            let _ = tokio::time::timeout(Duration::from_secs(5), driver_task)
                .await
                .unwrap();
        });

        let (server_result, client_result) = tokio::join!(server_task, client_task);
        server_result.unwrap();
        client_result.unwrap();
    }

    #[tokio::test]
    async fn server_driver_routes_follow_up_channels_into_the_accepted_conversation() {
        let (server_config, server_certificate) =
            self_signed_server_config(vec!["localhost".to_string()]).unwrap();
        let server_endpoint = h3_quinn::quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let mut client_endpoint = h3_quinn::quinn::Endpoint::client(SocketAddr::V4(
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        ))
        .unwrap();
        client_endpoint
            .set_default_client_config(client_config_for_certificate(server_certificate).unwrap());

        let client_connecting = client_endpoint.connect(server_addr, "localhost").unwrap();
        let (client_quinn, server_quinn) =
            tokio::join!(async { client_connecting.await.unwrap() }, async {
                let incoming = server_endpoint.accept().await.unwrap();
                incoming.await.unwrap()
            },);
        let (datagram_seen_tx, datagram_seen_rx) = oneshot::channel();

        let server_task = tokio::spawn(async move {
            let mut driver = ServerConnectionDriver::new(server_quinn).await.unwrap();
            let mut accepted = tokio::time::timeout(
                Duration::from_secs(5),
                driver.accept_conversation(30_000, 10),
            )
            .await
            .unwrap()
            .unwrap()
            .unwrap();

            accepted
                .control_stream
                .send_response(
                    response_with_server_header(StatusCode::OK, SSH3_VERSION_STRING).unwrap(),
                )
                .await
                .unwrap();

            let routed_conversation =
                tokio::time::timeout(Duration::from_secs(5), driver.accept_and_route_channel())
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(
                routed_conversation.control_stream_id(),
                accepted.conversation.control_stream_id()
            );

            let accepted_channel = tokio::time::timeout(
                Duration::from_secs(5),
                accepted.conversation.accept_channel_with_metadata(),
            )
            .await
            .unwrap()
            .unwrap();
            match accepted_channel {
                AcceptedChannel::UdpForwarding {
                    channel,
                    remote_addr,
                } => {
                    assert_eq!(
                        remote_addr,
                        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 44), 443))
                    );
                    channel.send_datagram(vec![9, 7, 5]).await.unwrap();
                    let _ = tokio::time::timeout(Duration::from_secs(5), datagram_seen_rx).await;
                }
                _ => panic!("expected UDP forwarding channel"),
            }
        });

        let client_task = tokio::spawn(async move {
            let client_quinn_for_close = client_quinn.clone();
            let (mut driver, mut send_request) = new_client(client_quinn.clone()).await.unwrap();
            let driver_task =
                tokio::spawn(async move { future::poll_fn(|cx| driver.poll_close(cx)).await });

            let established = tokio::time::timeout(
                Duration::from_secs(5),
                establish_client_conversation(
                    &mut send_request,
                    client_quinn.clone(),
                    build_connect_request(
                        "https://localhost/ssh3-term?user=tester".parse().unwrap(),
                        SSH3_VERSION_STRING,
                    )
                    .unwrap(),
                    30_000,
                    10,
                ),
            )
            .await
            .unwrap()
            .unwrap();

            let remote_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 44), 443));
            let channel = open_udp_forwarding_channel(
                established.conversation.as_ref(),
                &client_quinn,
                1024,
                10,
                remote_addr,
            )
            .await
            .unwrap();

            let datagram =
                tokio::time::timeout(Duration::from_secs(5), client_quinn.read_datagram())
                    .await
                    .unwrap()
                    .unwrap();
            let mut expected = Vec::new();
            ssh3_proto::append_var_int(&mut expected, established.conversation.control_stream_id());
            ssh3_proto::append_var_int(&mut expected, channel.channel_id());
            expected.extend_from_slice(&[9, 7, 5]);
            assert_eq!(datagram.as_ref(), expected);
            let _ = datagram_seen_tx.send(());

            client_quinn_for_close.close(0u32.into(), b"done");
            let _ = tokio::time::timeout(Duration::from_secs(5), driver_task)
                .await
                .unwrap();
        });

        let (server_result, client_result) = tokio::join!(server_task, client_task);
        server_result.unwrap();
        client_result.unwrap();
    }

    #[tokio::test]
    async fn server_driver_routes_datagrams_into_the_registered_conversation() {
        let (server_config, server_certificate) =
            self_signed_server_config(vec!["localhost".to_string()]).unwrap();
        let server_endpoint = h3_quinn::quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let mut client_endpoint = h3_quinn::quinn::Endpoint::client(SocketAddr::V4(
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        ))
        .unwrap();
        client_endpoint
            .set_default_client_config(client_config_for_certificate(server_certificate).unwrap());

        let client_connecting = client_endpoint.connect(server_addr, "localhost").unwrap();
        let (client_quinn, server_quinn) =
            tokio::join!(async { client_connecting.await.unwrap() }, async {
                let incoming = server_endpoint.accept().await.unwrap();
                incoming.await.unwrap()
            },);
        let (channel_ready_tx, channel_ready_rx) = oneshot::channel::<()>();
        let (datagram_seen_tx, datagram_seen_rx) = oneshot::channel::<()>();

        let server_task = async move {
            let mut driver = ServerConnectionDriver::new(server_quinn).await.unwrap();
            let mut accepted = tokio::time::timeout(
                Duration::from_secs(5),
                driver.accept_conversation(30_000, 10),
            )
            .await
            .unwrap()
            .unwrap()
            .unwrap();

            accepted
                .control_stream
                .send_response(
                    response_with_server_header(StatusCode::OK, SSH3_VERSION_STRING).unwrap(),
                )
                .await
                .unwrap();

            let _ = tokio::time::timeout(Duration::from_secs(5), driver.accept_and_route_channel())
                .await
                .unwrap()
                .unwrap();
            let accepted_channel = tokio::time::timeout(
                Duration::from_secs(5),
                accepted.conversation.accept_channel_with_metadata(),
            )
            .await
            .unwrap()
            .unwrap();
            let server_channel = match accepted_channel {
                AcceptedChannel::UdpForwarding {
                    channel,
                    remote_addr,
                } => {
                    assert_eq!(
                        remote_addr,
                        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 55), 9000))
                    );
                    channel
                }
                _ => panic!("expected UDP forwarding channel"),
            };
            let _ = channel_ready_tx.send(());

            let routed_conversation =
                tokio::time::timeout(Duration::from_secs(5), driver.accept_and_route_datagram())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
            assert_eq!(
                routed_conversation.control_stream_id(),
                accepted.conversation.control_stream_id()
            );
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(5), server_channel.receive_datagram())
                    .await
                    .unwrap(),
                vec![4, 3, 2, 1]
            );
            let _ = datagram_seen_tx.send(());
        };

        let client_task = async move {
            let client_quinn_for_close = client_quinn.clone();
            let (mut driver, mut send_request) = new_client(client_quinn.clone()).await.unwrap();
            let driver_task =
                tokio::spawn(async move { future::poll_fn(|cx| driver.poll_close(cx)).await });

            let established = tokio::time::timeout(
                Duration::from_secs(5),
                establish_client_conversation(
                    &mut send_request,
                    client_quinn.clone(),
                    build_connect_request(
                        "https://localhost/ssh3-term?user=tester".parse().unwrap(),
                        SSH3_VERSION_STRING,
                    )
                    .unwrap(),
                    30_000,
                    10,
                ),
            )
            .await
            .unwrap()
            .unwrap();

            let remote_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 55), 9000));
            let channel = open_udp_forwarding_channel(
                established.conversation.as_ref(),
                &client_quinn,
                1024,
                10,
                remote_addr,
            )
            .await
            .unwrap();
            let _ = tokio::time::timeout(Duration::from_secs(5), channel_ready_rx).await;
            channel.send_datagram(vec![4, 3, 2, 1]).await.unwrap();
            let _ = tokio::time::timeout(Duration::from_secs(5), datagram_seen_rx).await;

            client_quinn_for_close.close(0u32.into(), b"done");
            let _ = tokio::time::timeout(Duration::from_secs(5), driver_task)
                .await
                .unwrap();
        };

        let (server_result, client_result) = tokio::join!(server_task, client_task);
        let _ = server_result;
        let _ = client_result;
    }
}
