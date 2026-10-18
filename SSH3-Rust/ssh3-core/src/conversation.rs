use std::collections::HashMap;
use std::fmt;
use std::io::Cursor;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use ssh3_proto::{append_var_int, build_forwarding_additional_bytes, read_var_int};

use crate::channel::{AcceptedChannel, Channel, ChannelError};
use crate::queue::{AcceptQueue, DatagramQueue};
use crate::transport::{DatagramSender, ReceiveStream, SendStream};

pub type ConversationId = [u8; 32];

const DANGLING_DATAGRAM_QUEUE_SIZE: usize = 10;

#[derive(Debug)]
pub enum ConversationError {
    Channel(ChannelError),
    Proto(ssh3_proto::Error),
    ChannelNotFound { channel_id: u64 },
}

impl fmt::Display for ConversationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Channel(err) => write!(f, "{err}"),
            Self::Proto(err) => write!(f, "{err}"),
            Self::ChannelNotFound { channel_id } => write!(f, "channel not found: {channel_id}"),
        }
    }
}

impl std::error::Error for ConversationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Channel(err) => Some(err),
            Self::Proto(err) => Some(err),
            Self::ChannelNotFound { .. } => None,
        }
    }
}

impl From<ChannelError> for ConversationError {
    fn from(value: ChannelError) -> Self {
        Self::Channel(value)
    }
}

impl From<ssh3_proto::Error> for ConversationError {
    fn from(value: ssh3_proto::Error) -> Self {
        Self::Proto(value)
    }
}

#[derive(Clone)]
pub struct ConversationDatagramSender {
    control_stream_id: u64,
    channel_id: u64,
    message_sender: Arc<dyn DatagramSender>,
}

impl ConversationDatagramSender {
    pub fn new(
        control_stream_id: u64,
        channel_id: u64,
        message_sender: Arc<dyn DatagramSender>,
    ) -> Self {
        Self {
            control_stream_id,
            channel_id,
            message_sender,
        }
    }

    pub async fn send(&self, datagram: Vec<u8>) -> std::io::Result<()> {
        let mut buf = Vec::new();
        append_var_int(&mut buf, self.control_stream_id);
        append_var_int(&mut buf, self.channel_id);
        buf.extend_from_slice(&datagram);
        self.message_sender.send_datagram(buf).await
    }
}

pub struct Conversation {
    control_stream_id: u64,
    conversation_id: ConversationId,
    max_packet_size: u64,
    default_datagrams_queue_size: usize,
    message_sender: Arc<dyn DatagramSender>,
    channels_manager: ChannelsManager,
    channels_accept_queue: AcceptQueue<AcceptedChannel>,
}

impl Conversation {
    pub fn new(
        control_stream_id: u64,
        conversation_id: ConversationId,
        max_packet_size: u64,
        default_datagrams_queue_size: usize,
        message_sender: Arc<dyn DatagramSender>,
    ) -> Self {
        Self {
            control_stream_id,
            conversation_id,
            max_packet_size,
            default_datagrams_queue_size,
            message_sender,
            channels_manager: ChannelsManager::new(),
            channels_accept_queue: AcceptQueue::new(),
        }
    }

    pub fn open_channel<R, W>(
        &self,
        stream_id: u64,
        channel_type: impl Into<Vec<u8>>,
        max_packet_size: u64,
        datagrams_queue_size: usize,
        recv: R,
        send: W,
    ) -> Arc<Channel>
    where
        R: ReceiveStream + 'static,
        W: SendStream + 'static,
    {
        let channel = Arc::new(Channel::new(
            self.control_stream_id,
            self.conversation_id,
            stream_id,
            channel_type,
            max_packet_size,
            recv,
            send,
            None,
            true,
            true,
            false,
            datagrams_queue_size,
            None,
        ));
        self.channels_manager.add_channel(channel.clone());
        channel
    }

    pub fn datagram_sender_for_channel(&self, channel_id: u64) -> Arc<ConversationDatagramSender> {
        Arc::new(ConversationDatagramSender::new(
            self.control_stream_id,
            channel_id,
            self.message_sender.clone(),
        ))
    }

    pub async fn open_udp_forwarding_channel<R, W>(
        &self,
        stream_id: u64,
        max_packet_size: u64,
        datagrams_queue_size: usize,
        remote_addr: SocketAddr,
        recv: R,
        send: W,
    ) -> Result<Arc<Channel>, ConversationError>
    where
        R: ReceiveStream + 'static,
        W: SendStream + 'static,
    {
        let channel = Arc::new(Channel::new(
            self.control_stream_id,
            self.conversation_id,
            stream_id,
            b"direct-udp".to_vec(),
            max_packet_size,
            recv,
            send,
            Some(self.datagram_sender_for_channel(stream_id)),
            true,
            true,
            false,
            datagrams_queue_size,
            Some(&build_forwarding_additional_bytes(
                remote_addr.ip(),
                remote_addr.port(),
            )),
        ));
        channel.maybe_send_header().await?;
        self.channels_manager.add_channel(channel.clone());
        Ok(channel)
    }

    pub async fn open_tcp_forwarding_channel<R, W>(
        &self,
        stream_id: u64,
        max_packet_size: u64,
        datagrams_queue_size: usize,
        remote_addr: SocketAddr,
        recv: R,
        send: W,
    ) -> Result<Arc<Channel>, ConversationError>
    where
        R: ReceiveStream + 'static,
        W: SendStream + 'static,
    {
        let channel = Arc::new(Channel::new(
            self.control_stream_id,
            self.conversation_id,
            stream_id,
            b"direct-tcp".to_vec(),
            max_packet_size,
            recv,
            send,
            None,
            true,
            true,
            false,
            datagrams_queue_size,
            Some(&build_forwarding_additional_bytes(
                remote_addr.ip(),
                remote_addr.port(),
            )),
        ));
        channel.maybe_send_header().await?;
        self.channels_manager.add_channel(channel.clone());
        Ok(channel)
    }

    pub fn queue_incoming_channel(&self, channel: Arc<Channel>) {
        self.queue_incoming_accepted_channel(channel.into());
    }

    pub fn queue_incoming_accepted_channel(&self, channel: AcceptedChannel) {
        self.channels_accept_queue.add(channel);
    }

    pub async fn accept_channel(&self) -> Result<Arc<Channel>, ConversationError> {
        Ok(self.accept_channel_with_metadata().await?.into_channel())
    }

    pub async fn accept_channel_with_metadata(&self) -> Result<AcceptedChannel, ConversationError> {
        loop {
            if let Some(channel) = self.channels_accept_queue.next() {
                return self.confirm_and_register_channel(channel).await;
            }
            let channel = self.channels_accept_queue.wait_next().await;
            return self.confirm_and_register_channel(channel).await;
        }
    }

    pub async fn add_datagram(&self, datagram: &[u8]) -> Result<(), ConversationError> {
        let mut cursor = Cursor::new(datagram);
        let channel_id = read_var_int(&mut cursor)?;
        let offset = cursor.position() as usize;
        let payload = datagram[offset..].to_vec();

        if let Some(channel) = self.channels_manager.get_channel(channel_id) {
            channel.wait_add_datagram(payload).await;
            return Ok(());
        }

        let queue = Arc::new(DatagramQueue::new(DANGLING_DATAGRAM_QUEUE_SIZE));
        let _ = queue.add(payload);
        self.channels_manager
            .add_dangling_datagrams_queue(channel_id, queue);
        Err(ConversationError::ChannelNotFound { channel_id })
    }

    pub fn control_stream_id(&self) -> u64 {
        self.control_stream_id
    }

    pub fn conversation_id(&self) -> ConversationId {
        self.conversation_id
    }

    pub fn default_datagrams_queue_size(&self) -> usize {
        self.default_datagrams_queue_size
    }

    async fn confirm_and_register_channel(
        &self,
        channel: AcceptedChannel,
    ) -> Result<AcceptedChannel, ConversationError> {
        let inner = channel.channel().clone();
        inner.confirm_channel(self.max_packet_size).await?;
        self.channels_manager.add_channel(inner);
        Ok(channel)
    }
}

#[derive(Default)]
struct ChannelsState {
    channels: HashMap<u64, Arc<Channel>>,
    dangling_datagram_queues: HashMap<u64, Arc<DatagramQueue>>,
}

struct ChannelsManager {
    state: Mutex<ChannelsState>,
}

impl ChannelsManager {
    fn new() -> Self {
        Self {
            state: Mutex::new(ChannelsState::default()),
        }
    }

    fn add_channel(&self, channel: Arc<Channel>) {
        let pending_queue = {
            let mut state = self.state.lock().unwrap();
            let pending_queue = state.dangling_datagram_queues.remove(&channel.channel_id());
            state.channels.insert(channel.channel_id(), channel.clone());
            pending_queue
        };

        if let Some(queue) = pending_queue {
            channel.set_datagram_queue(queue);
        }
    }

    fn add_dangling_datagrams_queue(&self, channel_id: u64, queue: Arc<DatagramQueue>) {
        let existing_channel = {
            let mut state = self.state.lock().unwrap();
            if let Some(channel) = state.channels.get(&channel_id) {
                Some(channel.clone())
            } else {
                state
                    .dangling_datagram_queues
                    .insert(channel_id, queue.clone());
                None
            }
        };

        if let Some(channel) = existing_channel {
            while let Some(datagram) = queue.next() {
                channel.add_datagram(datagram);
            }
        }
    }

    fn get_channel(&self, channel_id: u64) -> Option<Arc<Channel>> {
        self.state
            .lock()
            .unwrap()
            .channels
            .get(&channel_id)
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::Arc;

    use ssh3_proto::{ChannelOpenConfirmationMessage, Message};

    use super::{Conversation, ConversationError};
    use crate::channel::{AcceptedChannel, Channel};
    use crate::transport::testutil::{
        BytesReceiveStream, RecordingDatagramSender, RecordingSendStream,
    };

    fn conversation_id() -> [u8; 32] {
        [9; 32]
    }

    #[tokio::test]
    async fn accept_channel_confirms_and_registers_channel() {
        let sender = Arc::new(RecordingDatagramSender::default());
        let conversation = Conversation::new(10, conversation_id(), 2048, 8, sender);
        let (recv, _) = BytesReceiveStream::new(Vec::new());
        let (send, handle) = RecordingSendStream::new();
        let incoming = Arc::new(Channel::new(
            10,
            conversation_id(),
            42,
            b"session".to_vec(),
            1024,
            recv,
            send,
            None,
            false,
            false,
            true,
            8,
            None,
        ));

        conversation.queue_incoming_channel(incoming.clone());
        let accepted = conversation.accept_channel().await.unwrap();

        assert!(Arc::ptr_eq(&accepted, &incoming));
        assert_eq!(
            handle.bytes(),
            Message::ChannelOpenConfirmation(ChannelOpenConfirmationMessage {
                max_packet_size: 2048,
            })
            .to_vec()
        );
    }

    #[tokio::test]
    async fn accept_channel_with_metadata_preserves_udp_forwarding_target() {
        let sender = Arc::new(RecordingDatagramSender::default());
        let conversation = Conversation::new(10, conversation_id(), 2048, 8, sender);
        let (recv, _) = BytesReceiveStream::new(Vec::new());
        let (send, handle) = RecordingSendStream::new();
        let incoming = Arc::new(Channel::new(
            10,
            conversation_id(),
            42,
            b"direct-udp".to_vec(),
            1024,
            recv,
            send,
            None,
            false,
            false,
            true,
            8,
            None,
        ));
        let remote_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 10), 443));

        conversation.queue_incoming_accepted_channel(AcceptedChannel::UdpForwarding {
            channel: incoming.clone(),
            remote_addr,
        });
        let accepted = conversation.accept_channel_with_metadata().await.unwrap();

        match accepted {
            AcceptedChannel::UdpForwarding {
                channel,
                remote_addr: accepted_remote_addr,
            } => {
                assert!(Arc::ptr_eq(&channel, &incoming));
                assert_eq!(accepted_remote_addr, remote_addr);
            }
            _ => panic!("expected UDP forwarding channel"),
        }
        assert_eq!(
            handle.bytes(),
            Message::ChannelOpenConfirmation(ChannelOpenConfirmationMessage {
                max_packet_size: 2048,
            })
            .to_vec()
        );
    }

    #[tokio::test]
    async fn accept_channel_with_metadata_preserves_tcp_forwarding_target() {
        let sender = Arc::new(RecordingDatagramSender::default());
        let conversation = Conversation::new(10, conversation_id(), 2048, 8, sender);
        let (recv, _) = BytesReceiveStream::new(Vec::new());
        let (send, handle) = RecordingSendStream::new();
        let incoming = Arc::new(Channel::new(
            10,
            conversation_id(),
            42,
            b"direct-tcp".to_vec(),
            1024,
            recv,
            send,
            None,
            false,
            false,
            true,
            8,
            None,
        ));
        let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 25)), 22);

        conversation.queue_incoming_accepted_channel(AcceptedChannel::TcpForwarding {
            channel: incoming.clone(),
            remote_addr,
        });
        let accepted = conversation.accept_channel_with_metadata().await.unwrap();

        match accepted {
            AcceptedChannel::TcpForwarding {
                channel,
                remote_addr: accepted_remote_addr,
            } => {
                assert!(Arc::ptr_eq(&channel, &incoming));
                assert_eq!(accepted_remote_addr, remote_addr);
            }
            _ => panic!("expected TCP forwarding channel"),
        }
        assert_eq!(
            handle.bytes(),
            Message::ChannelOpenConfirmation(ChannelOpenConfirmationMessage {
                max_packet_size: 2048,
            })
            .to_vec()
        );
    }

    #[tokio::test]
    async fn dangling_datagrams_are_delivered_when_channel_is_added() {
        let sender = Arc::new(RecordingDatagramSender::default());
        let conversation = Conversation::new(10, conversation_id(), 2048, 8, sender);

        let mut datagram = Vec::new();
        ssh3_proto::append_var_int(&mut datagram, 42);
        datagram.extend_from_slice(&[1, 2, 3]);

        match conversation.add_datagram(&datagram).await {
            Err(ConversationError::ChannelNotFound { channel_id }) => assert_eq!(channel_id, 42),
            other => panic!("expected missing channel error, got {other:?}"),
        }

        let (recv, _) = BytesReceiveStream::new(Vec::new());
        let (send, _) = RecordingSendStream::new();
        let channel = conversation.open_channel(42, b"session".to_vec(), 1024, 8, recv, send);

        assert_eq!(channel.receive_datagram().await, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn udp_forwarding_channels_send_prefixed_datagrams() {
        let sender = Arc::new(RecordingDatagramSender::default());
        let conversation = Conversation::new(10, conversation_id(), 2048, 8, sender.clone());
        let (recv, _) = BytesReceiveStream::new(Vec::new());
        let (send, _) = RecordingSendStream::new();

        let channel = conversation
            .open_udp_forwarding_channel(
                77,
                1024,
                8,
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 8), 443)),
                recv,
                send,
            )
            .await
            .unwrap();

        channel.send_datagram(vec![5, 4, 3]).await.unwrap();

        let mut expected = Vec::new();
        ssh3_proto::append_var_int(&mut expected, 10);
        ssh3_proto::append_var_int(&mut expected, 77);
        expected.extend_from_slice(&[5, 4, 3]);
        assert_eq!(sender.datagrams(), vec![expected]);
    }

    #[tokio::test]
    async fn tcp_forwarding_channels_write_forwarding_headers_immediately() {
        let sender = Arc::new(RecordingDatagramSender::default());
        let conversation = Conversation::new(10, conversation_id(), 2048, 8, sender);
        let (recv, _) = BytesReceiveStream::new(Vec::new());
        let (send, handle) = RecordingSendStream::new();

        let _channel = conversation
            .open_tcp_forwarding_channel(
                77,
                1024,
                8,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)), 22),
                recv,
                send,
            )
            .await
            .unwrap();

        let expected = ssh3_proto::ChannelHeader {
            conversation_stream_id: 10,
            channel_type: b"direct-tcp".to_vec(),
            max_packet_size: 1024,
        }
        .encode(Some(&ssh3_proto::build_forwarding_additional_bytes(
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            22,
        )));
        assert_eq!(handle.bytes(), expected);
    }
}
