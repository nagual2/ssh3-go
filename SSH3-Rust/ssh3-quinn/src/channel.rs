use std::fmt;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::sync::Mutex;

use quinn::{Connection, ConnectionError, RecvStream};
use ssh3_core::{
    AcceptedChannel, Channel, Conversation, ConversationDatagramSender, ConversationError,
    ConversationId,
};
use ssh3_proto::{ChannelHeader, ForwardingAddressFamily, SSH_FRAME_TYPE};

use crate::{QuinnReceiveStream, QuinnSendStream, read_exact_error_to_io};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IncomingChannel {
    pub stream_id: u64,
    pub header: ChannelHeader,
    pub forwarding_target: Option<SocketAddr>,
}

impl IncomingChannel {
    pub fn into_accepted_channel(
        self,
        conversation_id: ConversationId,
        recv: quinn::RecvStream,
        send: quinn::SendStream,
        datagram_sender: Option<Arc<ConversationDatagramSender>>,
        datagrams_queue_size: usize,
    ) -> AcceptedChannel {
        let stream_id = self.stream_id;
        let forwarding_target = self.forwarding_target;
        let channel_type = self.header.channel_type.clone();
        let datagram_sender = if channel_type.as_slice() == b"direct-udp" {
            datagram_sender
        } else {
            None
        };
        let channel = Arc::new(Channel::new(
            self.header.conversation_stream_id,
            conversation_id,
            stream_id,
            self.header.channel_type,
            self.header.max_packet_size,
            QuinnReceiveStream::new(recv),
            QuinnSendStream::new(send),
            datagram_sender,
            false,
            false,
            true,
            datagrams_queue_size,
            None,
        ));

        match (channel_type.as_slice(), forwarding_target) {
            (b"direct-udp", Some(remote_addr)) => AcceptedChannel::UdpForwarding {
                channel,
                remote_addr,
            },
            (b"direct-tcp", Some(remote_addr)) => AcceptedChannel::TcpForwarding {
                channel,
                remote_addr,
            },
            _ => AcceptedChannel::Channel(channel),
        }
    }

    pub fn into_accepted_channel_for_conversation(
        self,
        conversation: &Conversation,
        recv: quinn::RecvStream,
        send: quinn::SendStream,
    ) -> AcceptedChannel {
        let datagram_sender = (self.header.channel_type.as_slice() == b"direct-udp")
            .then(|| conversation.datagram_sender_for_channel(self.stream_id));
        self.into_accepted_channel(
            conversation.conversation_id(),
            recv,
            send,
            datagram_sender,
            conversation.default_datagrams_queue_size(),
        )
    }

    pub fn into_channel(
        self,
        conversation_id: ConversationId,
        recv: quinn::RecvStream,
        send: quinn::SendStream,
        datagram_sender: Option<Arc<ConversationDatagramSender>>,
        datagrams_queue_size: usize,
    ) -> Arc<Channel> {
        self.into_accepted_channel(
            conversation_id,
            recv,
            send,
            datagram_sender,
            datagrams_queue_size,
        )
        .into_channel()
    }
}

#[derive(Default)]
pub struct IncomingChannelRouter {
    conversations: Mutex<std::collections::HashMap<u64, Arc<Conversation>>>,
}

impl IncomingChannelRouter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_conversation(&self, conversation: Arc<Conversation>) {
        self.conversations
            .lock()
            .unwrap()
            .insert(conversation.control_stream_id(), conversation);
    }

    pub fn unregister_conversation(&self, control_stream_id: u64) -> Option<Arc<Conversation>> {
        self.conversations
            .lock()
            .unwrap()
            .remove(&control_stream_id)
    }

    pub fn conversation(&self, control_stream_id: u64) -> Option<Arc<Conversation>> {
        self.conversations
            .lock()
            .unwrap()
            .get(&control_stream_id)
            .cloned()
    }

    pub fn route_incoming_channel(
        &self,
        incoming: IncomingChannel,
        send: quinn::SendStream,
        recv: quinn::RecvStream,
    ) -> Result<Arc<Conversation>, RouteIncomingChannelError> {
        let control_stream_id = incoming.header.conversation_stream_id;
        let channel_id = incoming.stream_id;
        let Some(conversation) = self.conversation(control_stream_id) else {
            return Err(RouteIncomingChannelError::UnknownConversation {
                control_stream_id,
                channel_id,
            });
        };

        conversation.queue_incoming_accepted_channel(
            incoming.into_accepted_channel_for_conversation(conversation.as_ref(), recv, send),
        );
        Ok(conversation)
    }

    pub async fn accept_and_route_channel(
        &self,
        connection: &Connection,
    ) -> Result<Arc<Conversation>, RouteAcceptedChannelError> {
        let (incoming, send, recv) = accept_bi_channel(connection).await?;
        self.route_incoming_channel(incoming, send, recv)
            .map_err(RouteAcceptedChannelError::Route)
    }

    pub async fn accept_and_route_channels_forever(
        self: Arc<Self>,
        connection: Connection,
    ) -> Result<(), RouteAcceptedChannelError> {
        loop {
            self.accept_and_route_channel(&connection).await?;
        }
    }
}

#[derive(Debug)]
pub enum ChannelSetupError {
    Io(io::Error),
    Proto(ssh3_proto::Error),
    UnexpectedFrameType { frame_type: u64 },
}

impl fmt::Display for ChannelSetupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::Proto(err) => write!(f, "{err}"),
            Self::UnexpectedFrameType { frame_type } => {
                write!(f, "unexpected SSH3 frame type: {frame_type}")
            }
        }
    }
}

impl std::error::Error for ChannelSetupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Proto(err) => Some(err),
            Self::UnexpectedFrameType { .. } => None,
        }
    }
}

impl From<io::Error> for ChannelSetupError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<ssh3_proto::Error> for ChannelSetupError {
    fn from(value: ssh3_proto::Error) -> Self {
        Self::Proto(value)
    }
}

#[derive(Debug)]
pub enum AcceptChannelError {
    Connection(ConnectionError),
    Setup(ChannelSetupError),
}

impl fmt::Display for AcceptChannelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connection(err) => write!(f, "{err}"),
            Self::Setup(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for AcceptChannelError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Connection(err) => Some(err),
            Self::Setup(err) => Some(err),
        }
    }
}

impl From<ConnectionError> for AcceptChannelError {
    fn from(value: ConnectionError) -> Self {
        Self::Connection(value)
    }
}

impl From<ChannelSetupError> for AcceptChannelError {
    fn from(value: ChannelSetupError) -> Self {
        Self::Setup(value)
    }
}

#[derive(Debug)]
pub enum OpenChannelError {
    Connection(ConnectionError),
    Conversation(ConversationError),
}

impl fmt::Display for OpenChannelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connection(err) => write!(f, "{err}"),
            Self::Conversation(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for OpenChannelError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Connection(err) => Some(err),
            Self::Conversation(err) => Some(err),
        }
    }
}

impl From<ConnectionError> for OpenChannelError {
    fn from(value: ConnectionError) -> Self {
        Self::Connection(value)
    }
}

impl From<ConversationError> for OpenChannelError {
    fn from(value: ConversationError) -> Self {
        Self::Conversation(value)
    }
}

#[derive(Debug)]
pub enum RouteIncomingChannelError {
    UnknownConversation {
        control_stream_id: u64,
        channel_id: u64,
    },
}

impl fmt::Display for RouteIncomingChannelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownConversation {
                control_stream_id,
                channel_id,
            } => write!(
                f,
                "no registered conversation for control stream {} while routing channel {}",
                control_stream_id, channel_id
            ),
        }
    }
}

impl std::error::Error for RouteIncomingChannelError {}

#[derive(Debug)]
pub enum RouteAcceptedChannelError {
    Accept(AcceptChannelError),
    Route(RouteIncomingChannelError),
}

impl fmt::Display for RouteAcceptedChannelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Accept(err) => write!(f, "{err}"),
            Self::Route(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for RouteAcceptedChannelError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Accept(err) => Some(err),
            Self::Route(err) => Some(err),
        }
    }
}

impl From<AcceptChannelError> for RouteAcceptedChannelError {
    fn from(value: AcceptChannelError) -> Self {
        Self::Accept(value)
    }
}

pub async fn accept_bi_channel(
    connection: &Connection,
) -> Result<(IncomingChannel, quinn::SendStream, quinn::RecvStream), AcceptChannelError> {
    let (send, mut recv) = connection.accept_bi().await?;
    let incoming = read_incoming_channel(&mut recv).await?;
    Ok((incoming, send, recv))
}

pub async fn read_incoming_channel(
    recv: &mut RecvStream,
) -> Result<IncomingChannel, ChannelSetupError> {
    let frame_type = read_var_int(recv).await?;
    if frame_type != SSH_FRAME_TYPE {
        return Err(ChannelSetupError::UnexpectedFrameType { frame_type });
    }

    let header = ChannelHeader {
        conversation_stream_id: read_var_int(recv).await?,
        channel_type: read_ssh_bytes(recv).await?,
        max_packet_size: read_var_int(recv).await?,
    };

    let forwarding_target = match header.channel_type.as_slice() {
        b"direct-udp" | b"direct-tcp" => Some(read_forwarding_target(recv).await?),
        _ => None,
    };

    Ok(IncomingChannel {
        stream_id: recv.id().into(),
        header,
        forwarding_target,
    })
}

pub async fn open_channel(
    conversation: &Conversation,
    connection: &Connection,
    channel_type: impl Into<Vec<u8>>,
    max_packet_size: u64,
    datagrams_queue_size: usize,
) -> Result<Arc<Channel>, OpenChannelError> {
    let (send, recv) = connection.open_bi().await?;
    Ok(conversation.open_channel(
        send.id().into(),
        channel_type,
        max_packet_size,
        datagrams_queue_size,
        QuinnReceiveStream::new(recv),
        QuinnSendStream::new(send),
    ))
}

pub async fn open_udp_forwarding_channel(
    conversation: &Conversation,
    connection: &Connection,
    max_packet_size: u64,
    datagrams_queue_size: usize,
    remote_addr: SocketAddr,
) -> Result<Arc<Channel>, OpenChannelError> {
    let (send, recv) = connection.open_bi().await?;
    conversation
        .open_udp_forwarding_channel(
            send.id().into(),
            max_packet_size,
            datagrams_queue_size,
            remote_addr,
            QuinnReceiveStream::new(recv),
            QuinnSendStream::new(send),
        )
        .await
        .map_err(OpenChannelError::from)
}

pub async fn open_tcp_forwarding_channel(
    conversation: &Conversation,
    connection: &Connection,
    max_packet_size: u64,
    datagrams_queue_size: usize,
    remote_addr: SocketAddr,
) -> Result<Arc<Channel>, OpenChannelError> {
    let (send, recv) = connection.open_bi().await?;
    conversation
        .open_tcp_forwarding_channel(
            send.id().into(),
            max_packet_size,
            datagrams_queue_size,
            remote_addr,
            QuinnReceiveStream::new(recv),
            QuinnSendStream::new(send),
        )
        .await
        .map_err(OpenChannelError::from)
}

async fn read_forwarding_target(recv: &mut RecvStream) -> Result<SocketAddr, ChannelSetupError> {
    let family = ForwardingAddressFamily::try_from(read_var_int(recv).await?)?;
    let mut octets = match family {
        ForwardingAddressFamily::Ipv4 => vec![0; 4],
        ForwardingAddressFamily::Ipv6 => vec![0; 16],
    };
    read_exact(recv, &mut octets).await?;

    let mut port = [0; 2];
    read_exact(recv, &mut port).await?;
    let port = u16::from_be_bytes(port);

    match family {
        ForwardingAddressFamily::Ipv4 => {
            let ip = Ipv4Addr::from(<[u8; 4]>::try_from(octets).unwrap());
            Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
        }
        ForwardingAddressFamily::Ipv6 => {
            let ip = Ipv6Addr::from(<[u8; 16]>::try_from(octets).unwrap());
            Ok(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)))
        }
    }
}

async fn read_var_int(recv: &mut RecvStream) -> Result<u64, ChannelSetupError> {
    let first_byte = read_byte(recv).await?;
    let len = 1 << ((first_byte & 0xc0) >> 6);
    let b1 = first_byte & 0x3f;
    if len == 1 {
        return Ok(u64::from(b1));
    }

    let b2 = read_byte(recv).await?;
    if len == 2 {
        return Ok(u64::from(b2) + (u64::from(b1) << 8));
    }

    let b3 = read_byte(recv).await?;
    let b4 = read_byte(recv).await?;
    if len == 4 {
        return Ok(u64::from(b4)
            + (u64::from(b3) << 8)
            + (u64::from(b2) << 16)
            + (u64::from(b1) << 24));
    }

    let b5 = read_byte(recv).await?;
    let b6 = read_byte(recv).await?;
    let b7 = read_byte(recv).await?;
    let b8 = read_byte(recv).await?;
    Ok(u64::from(b8)
        + (u64::from(b7) << 8)
        + (u64::from(b6) << 16)
        + (u64::from(b5) << 24)
        + (u64::from(b4) << 32)
        + (u64::from(b3) << 40)
        + (u64::from(b2) << 48)
        + (u64::from(b1) << 56))
}

async fn read_ssh_bytes(recv: &mut RecvStream) -> Result<Vec<u8>, ChannelSetupError> {
    let len = read_var_int(recv).await?;
    let len = usize::try_from(len)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "SSH string too large"))?;
    let mut out = vec![0; len];
    read_exact(recv, &mut out).await?;
    Ok(out)
}

async fn read_byte(recv: &mut RecvStream) -> Result<u8, ChannelSetupError> {
    let mut byte = [0; 1];
    read_exact(recv, &mut byte).await?;
    Ok(byte[0])
}

async fn read_exact(recv: &mut RecvStream, buf: &mut [u8]) -> Result<(), ChannelSetupError> {
    recv.read_exact(buf)
        .await
        .map_err(read_exact_error_to_io)
        .map_err(ChannelSetupError::from)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::Arc;
    use std::time::Duration;

    use ssh3_core::{AcceptedChannel, Conversation};
    use ssh3_proto::{ChannelRequest, ChannelRequestMessage, Message, append_var_int};

    use super::{
        IncomingChannelRouter, RouteAcceptedChannelError, accept_bi_channel, open_channel,
        open_tcp_forwarding_channel, open_udp_forwarding_channel,
    };
    use crate::{QuinnDatagramSender, client_config_for_certificate, self_signed_server_config};

    fn conversation_id() -> [u8; 32] {
        [7; 32]
    }

    async fn loopback() -> (
        quinn::Endpoint,
        quinn::Endpoint,
        quinn::Connection,
        quinn::Connection,
    ) {
        let (server_config, server_certificate) =
            self_signed_server_config(vec!["localhost".to_string()]).unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let mut client_endpoint =
            quinn::Endpoint::client(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
                .unwrap();
        client_endpoint
            .set_default_client_config(client_config_for_certificate(server_certificate).unwrap());

        let client_connecting = client_endpoint.connect(server_addr, "localhost").unwrap();
        let (client_connection, server_connection) = tokio::join!(
            async {
                tokio::time::timeout(Duration::from_secs(5), client_connecting)
                    .await
                    .unwrap()
                    .unwrap()
            },
            async {
                let incoming =
                    tokio::time::timeout(Duration::from_secs(5), server_endpoint.accept())
                        .await
                        .unwrap()
                        .unwrap();
                tokio::time::timeout(Duration::from_secs(5), incoming)
                    .await
                    .unwrap()
                    .unwrap()
            },
        );
        (
            client_endpoint,
            server_endpoint,
            client_connection,
            server_connection,
        )
    }

    #[tokio::test]
    async fn incoming_channels_round_trip_with_core_messages() {
        let (_client_endpoint, _server_endpoint, client_connection, server_connection) =
            loopback().await;

        let conversation = Conversation::new(
            5,
            conversation_id(),
            4096,
            8,
            Arc::new(QuinnDatagramSender::new(client_connection.clone())),
        );
        let client_channel = open_channel(
            &conversation,
            &client_connection,
            b"session".to_vec(),
            1024,
            8,
        )
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(5), client_channel.maybe_send_header())
            .await
            .unwrap()
            .unwrap();

        let (incoming, send, recv) = tokio::time::timeout(
            Duration::from_secs(5),
            accept_bi_channel(&server_connection),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(incoming.header.conversation_stream_id, 5);
        assert_eq!(incoming.header.channel_type, b"session".to_vec());
        assert_eq!(incoming.forwarding_target, None);

        let server_channel = incoming.into_channel(conversation_id(), recv, send, None, 8);
        tokio::time::timeout(Duration::from_secs(5), server_channel.confirm_channel(2048))
            .await
            .unwrap()
            .unwrap();

        let request = ChannelRequestMessage {
            want_reply: true,
            request: ChannelRequest::Shell,
        };
        tokio::time::timeout(
            Duration::from_secs(5),
            client_channel.send_request(request.clone()),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), server_channel.next_message())
                .await
                .unwrap()
                .unwrap(),
            Message::ChannelRequest(request)
        );
    }

    #[tokio::test]
    async fn udp_forwarding_channels_send_quic_datagrams() {
        let (_client_endpoint, _server_endpoint, client_connection, server_connection) =
            loopback().await;

        let client_conversation = Conversation::new(
            11,
            conversation_id(),
            4096,
            8,
            Arc::new(QuinnDatagramSender::new(client_connection.clone())),
        );
        let server_conversation = Conversation::new(
            11,
            conversation_id(),
            4096,
            8,
            Arc::new(QuinnDatagramSender::new(server_connection.clone())),
        );
        let remote_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 10), 443));
        let client_channel = open_udp_forwarding_channel(
            &client_conversation,
            &client_connection,
            1024,
            8,
            remote_addr,
        )
        .await
        .unwrap();

        let (incoming, send, recv) = tokio::time::timeout(
            Duration::from_secs(5),
            accept_bi_channel(&server_connection),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(incoming.header.channel_type, b"direct-udp".to_vec());
        assert_eq!(incoming.forwarding_target, Some(remote_addr));

        server_conversation.queue_incoming_accepted_channel(
            incoming.into_accepted_channel_for_conversation(&server_conversation, recv, send),
        );
        let accepted = tokio::time::timeout(
            Duration::from_secs(5),
            server_conversation.accept_channel_with_metadata(),
        )
        .await
        .unwrap()
        .unwrap();
        let server_channel = match accepted {
            AcceptedChannel::UdpForwarding {
                channel,
                remote_addr: accepted_remote_addr,
            } => {
                assert_eq!(accepted_remote_addr, remote_addr);
                channel
            }
            _ => panic!("expected UDP forwarding channel"),
        };

        tokio::time::timeout(
            Duration::from_secs(5),
            client_channel.send_datagram(vec![1, 2, 3, 4]),
        )
        .await
        .unwrap()
        .unwrap();
        let client_to_server_datagram =
            tokio::time::timeout(Duration::from_secs(5), server_connection.read_datagram())
                .await
                .unwrap()
                .unwrap();

        let mut expected = Vec::new();
        append_var_int(&mut expected, 11);
        append_var_int(&mut expected, client_channel.channel_id());
        expected.extend_from_slice(&[1, 2, 3, 4]);
        assert_eq!(client_to_server_datagram.as_ref(), expected);

        tokio::time::timeout(
            Duration::from_secs(5),
            server_channel.send_datagram(vec![9, 8, 7]),
        )
        .await
        .unwrap()
        .unwrap();
        let server_to_client_datagram =
            tokio::time::timeout(Duration::from_secs(5), client_connection.read_datagram())
                .await
                .unwrap()
                .unwrap();

        let mut expected = Vec::new();
        append_var_int(&mut expected, 11);
        append_var_int(&mut expected, server_channel.channel_id());
        expected.extend_from_slice(&[9, 8, 7]);
        assert_eq!(server_to_client_datagram.as_ref(), expected);
    }

    #[tokio::test]
    async fn tcp_forwarding_channels_accept_as_typed_forwarding_channels() {
        let (_client_endpoint, _server_endpoint, client_connection, server_connection) =
            loopback().await;

        let conversation = Conversation::new(
            12,
            conversation_id(),
            4096,
            8,
            Arc::new(QuinnDatagramSender::new(server_connection.clone())),
        );
        let remote_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 7), 22));
        let _channel =
            open_tcp_forwarding_channel(&conversation, &client_connection, 1024, 8, remote_addr)
                .await
                .unwrap();

        let (incoming, send, recv) = tokio::time::timeout(
            Duration::from_secs(5),
            accept_bi_channel(&server_connection),
        )
        .await
        .unwrap()
        .unwrap();

        let accepted = incoming.into_accepted_channel_for_conversation(&conversation, recv, send);
        match accepted {
            AcceptedChannel::TcpForwarding {
                channel,
                remote_addr: accepted_remote_addr,
            } => {
                assert_eq!(channel.channel_type(), b"direct-tcp");
                assert_eq!(accepted_remote_addr, remote_addr);
            }
            _ => panic!("expected TCP forwarding channel"),
        }
    }

    #[tokio::test]
    async fn router_queues_channels_for_registered_conversations() {
        let (_client_endpoint, _server_endpoint, client_connection, server_connection) =
            loopback().await;

        let control_stream_id = 21;
        let client_conversation = Conversation::new(
            control_stream_id,
            conversation_id(),
            4096,
            8,
            Arc::new(QuinnDatagramSender::new(client_connection.clone())),
        );
        let server_conversation = Arc::new(Conversation::new(
            control_stream_id,
            conversation_id(),
            4096,
            8,
            Arc::new(QuinnDatagramSender::new(server_connection.clone())),
        ));
        let router = IncomingChannelRouter::new();
        router.register_conversation(server_conversation.clone());

        let remote_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 15), 5353));
        let client_channel = open_udp_forwarding_channel(
            &client_conversation,
            &client_connection,
            1024,
            8,
            remote_addr,
        )
        .await
        .unwrap();

        let routed_conversation = tokio::time::timeout(
            Duration::from_secs(5),
            router.accept_and_route_channel(&server_connection),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(Arc::ptr_eq(&routed_conversation, &server_conversation));

        let accepted = tokio::time::timeout(
            Duration::from_secs(5),
            server_conversation.accept_channel_with_metadata(),
        )
        .await
        .unwrap()
        .unwrap();
        let server_channel = match accepted {
            AcceptedChannel::UdpForwarding {
                channel,
                remote_addr: accepted_remote_addr,
            } => {
                assert_eq!(accepted_remote_addr, remote_addr);
                channel
            }
            _ => panic!("expected UDP forwarding channel"),
        };

        tokio::time::timeout(
            Duration::from_secs(5),
            client_channel.send_datagram(vec![6, 5, 4]),
        )
        .await
        .unwrap()
        .unwrap();
        let mut expected = Vec::new();
        append_var_int(&mut expected, control_stream_id);
        append_var_int(&mut expected, client_channel.channel_id());
        expected.extend_from_slice(&[6, 5, 4]);
        let datagram =
            tokio::time::timeout(Duration::from_secs(5), server_connection.read_datagram())
                .await
                .unwrap()
                .unwrap();
        assert_eq!(datagram.as_ref(), expected);

        tokio::time::timeout(
            Duration::from_secs(5),
            server_channel.send_datagram(vec![1, 1, 2, 3]),
        )
        .await
        .unwrap()
        .unwrap();
        let mut expected = Vec::new();
        append_var_int(&mut expected, control_stream_id);
        append_var_int(&mut expected, server_channel.channel_id());
        expected.extend_from_slice(&[1, 1, 2, 3]);
        let datagram =
            tokio::time::timeout(Duration::from_secs(5), client_connection.read_datagram())
                .await
                .unwrap()
                .unwrap();
        assert_eq!(datagram.as_ref(), expected);
    }

    #[tokio::test]
    async fn router_rejects_unknown_conversations() {
        let (_client_endpoint, _server_endpoint, client_connection, server_connection) =
            loopback().await;

        let client_conversation = Conversation::new(
            33,
            conversation_id(),
            4096,
            8,
            Arc::new(QuinnDatagramSender::new(client_connection.clone())),
        );
        let router = IncomingChannelRouter::new();

        let channel = open_channel(
            &client_conversation,
            &client_connection,
            b"session".to_vec(),
            1024,
            8,
        )
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(5), channel.maybe_send_header())
            .await
            .unwrap()
            .unwrap();

        match tokio::time::timeout(
            Duration::from_secs(5),
            router.accept_and_route_channel(&server_connection),
        )
        .await
        .unwrap()
        {
            Err(RouteAcceptedChannelError::Route(
                super::RouteIncomingChannelError::UnknownConversation {
                    control_stream_id,
                    channel_id,
                },
            )) => {
                assert_eq!(control_stream_id, 33);
                assert_eq!(channel_id % 4, 0);
            }
            _ => panic!("expected routing error"),
        }
    }
}
