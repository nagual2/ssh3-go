use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use ssh3_proto::{
    ChannelHeader, ChannelOpenConfirmationMessage, ChannelOpenFailureMessage,
    ChannelRequestMessage, DataOrExtendedDataMessage, Message, SSH_EXTENDED_DATA_NONE, SshDataType,
};
use tokio::sync::Mutex as AsyncMutex;

use crate::conversation::{ConversationDatagramSender, ConversationId};
use crate::queue::DatagramQueue;
use crate::transport::{ReceiveStream, SendStream};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelInfo {
    pub max_packet_size: u64,
    pub conversation_stream_id: u64,
    pub conversation_id: ConversationId,
    pub channel_id: u64,
    pub channel_type: Vec<u8>,
}

#[derive(Clone)]
pub enum AcceptedChannel {
    Channel(Arc<Channel>),
    UdpForwarding {
        channel: Arc<Channel>,
        remote_addr: SocketAddr,
    },
    TcpForwarding {
        channel: Arc<Channel>,
        remote_addr: SocketAddr,
    },
}

impl AcceptedChannel {
    pub fn channel(&self) -> &Arc<Channel> {
        match self {
            Self::Channel(channel)
            | Self::UdpForwarding { channel, .. }
            | Self::TcpForwarding { channel, .. } => channel,
        }
    }

    pub fn into_channel(self) -> Arc<Channel> {
        match self {
            Self::Channel(channel)
            | Self::UdpForwarding { channel, .. }
            | Self::TcpForwarding { channel, .. } => channel,
        }
    }

    pub fn remote_addr(&self) -> Option<SocketAddr> {
        match self {
            Self::Channel(_) => None,
            Self::UdpForwarding { remote_addr, .. } | Self::TcpForwarding { remote_addr, .. } => {
                Some(*remote_addr)
            }
        }
    }
}

impl From<Arc<Channel>> for AcceptedChannel {
    fn from(value: Arc<Channel>) -> Self {
        Self::Channel(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelOpenFailure {
    pub reason_code: u64,
    pub error_message_utf8: Vec<u8>,
}

impl fmt::Display for ChannelOpenFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "channel open failure: reason {}: {}",
            self.reason_code,
            String::from_utf8_lossy(&self.error_message_utf8)
        )
    }
}

impl std::error::Error for ChannelOpenFailure {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageOnNonConfirmedChannel {
    pub message: Message,
}

impl fmt::Display for MessageOnNonConfirmedChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "message {:?} received on a non-confirmed channel",
            self.message
        )
    }
}

impl std::error::Error for MessageOnNonConfirmedChannel {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SentDatagramOnNonDatagramChannel {
    pub channel_id: u64,
}

impl fmt::Display for SentDatagramOnNonDatagramChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "datagram sent on non-datagram channel {}",
            self.channel_id
        )
    }
}

impl std::error::Error for SentDatagramOnNonDatagramChannel {}

#[derive(Debug)]
pub enum ChannelError {
    Io(io::Error),
    Proto(ssh3_proto::Error),
    OpenFailure(ChannelOpenFailure),
    NonConfirmed(MessageOnNonConfirmedChannel),
    DatagramSenderMissing(SentDatagramOnNonDatagramChannel),
    MaxPacketSizeTooSmall {
        max_packet_size: u64,
        message_overhead: usize,
    },
}

impl fmt::Display for ChannelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::Proto(err) => write!(f, "{err}"),
            Self::OpenFailure(err) => write!(f, "{err}"),
            Self::NonConfirmed(err) => write!(f, "{err}"),
            Self::DatagramSenderMissing(err) => write!(f, "{err}"),
            Self::MaxPacketSizeTooSmall {
                max_packet_size,
                message_overhead,
            } => write!(
                f,
                "max packet size {} is too small for message overhead {}",
                max_packet_size, message_overhead
            ),
        }
    }
}

impl std::error::Error for ChannelError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Proto(err) => Some(err),
            Self::OpenFailure(err) => Some(err),
            Self::NonConfirmed(err) => Some(err),
            Self::DatagramSenderMissing(err) => Some(err),
            Self::MaxPacketSizeTooSmall { .. } => None,
        }
    }
}

impl From<io::Error> for ChannelError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<ssh3_proto::Error> for ChannelError {
    fn from(value: ssh3_proto::Error) -> Self {
        Self::Proto(value)
    }
}

pub struct Channel {
    info: ChannelInfo,
    confirm_sent: AtomicBool,
    confirm_received: AtomicBool,
    header: Mutex<Option<Vec<u8>>>,
    datagram_sender: RwLock<Option<Arc<ConversationDatagramSender>>>,
    recv: AsyncMutex<Box<dyn ReceiveStream>>,
    send: AsyncMutex<Box<dyn SendStream>>,
    datagrams_queue: RwLock<Arc<DatagramQueue>>,
}

impl Channel {
    #[allow(clippy::too_many_arguments)]
    pub fn new<R, W>(
        conversation_stream_id: u64,
        conversation_id: ConversationId,
        channel_id: u64,
        channel_type: impl Into<Vec<u8>>,
        max_packet_size: u64,
        recv: R,
        send: W,
        datagram_sender: Option<Arc<ConversationDatagramSender>>,
        send_header: bool,
        confirm_sent: bool,
        confirm_received: bool,
        datagrams_queue_size: usize,
        additional_header_bytes: Option<&[u8]>,
    ) -> Self
    where
        R: ReceiveStream + 'static,
        W: SendStream + 'static,
    {
        let channel_type = channel_type.into();
        let header = send_header.then(|| {
            ChannelHeader {
                conversation_stream_id,
                channel_type: channel_type.clone(),
                max_packet_size,
            }
            .encode(additional_header_bytes)
        });

        Self {
            info: ChannelInfo {
                max_packet_size,
                conversation_stream_id,
                conversation_id,
                channel_id,
                channel_type,
            },
            confirm_sent: AtomicBool::new(confirm_sent),
            confirm_received: AtomicBool::new(confirm_received),
            header: Mutex::new(header),
            datagram_sender: RwLock::new(datagram_sender),
            recv: AsyncMutex::new(Box::new(recv)),
            send: AsyncMutex::new(Box::new(send)),
            datagrams_queue: RwLock::new(Arc::new(DatagramQueue::new(datagrams_queue_size))),
        }
    }

    pub fn info(&self) -> &ChannelInfo {
        &self.info
    }

    pub fn channel_id(&self) -> u64 {
        self.info.channel_id
    }

    pub fn conversation_id(&self) -> ConversationId {
        self.info.conversation_id
    }

    pub fn conversation_stream_id(&self) -> u64 {
        self.info.conversation_stream_id
    }

    pub fn max_packet_size(&self) -> u64 {
        self.info.max_packet_size
    }

    pub fn channel_type(&self) -> &[u8] {
        &self.info.channel_type
    }

    pub fn confirm_received(&self) -> bool {
        self.confirm_received.load(Ordering::SeqCst)
    }

    pub async fn wait_for_confirmation(&self) -> Result<(), ChannelError> {
        if self.confirm_received() {
            return Ok(());
        }

        loop {
            let message = {
                let mut recv = self.recv.lock().await;
                parse_message(recv.as_mut()).await?
            };

            match message {
                Message::ChannelOpenConfirmation(_) => {
                    self.confirm_received.store(true, Ordering::SeqCst);
                    return Ok(());
                }
                Message::ChannelOpenFailure(message) => {
                    return Err(ChannelError::OpenFailure(ChannelOpenFailure {
                        reason_code: message.reason_code,
                        error_message_utf8: message.error_message_utf8,
                    }));
                }
                other => {
                    return Err(ChannelError::NonConfirmed(MessageOnNonConfirmedChannel {
                        message: other,
                    }));
                }
            }
        }
    }

    pub async fn next_message(&self) -> Result<Message, ChannelError> {
        loop {
            let message = {
                let mut recv = self.recv.lock().await;
                parse_message(recv.as_mut()).await?
            };

            match message {
                Message::ChannelOpenConfirmation(_) => {
                    self.confirm_received.store(true, Ordering::SeqCst);
                    continue;
                }
                Message::ChannelOpenFailure(message) => {
                    return Err(ChannelError::OpenFailure(ChannelOpenFailure {
                        reason_code: message.reason_code,
                        error_message_utf8: message.error_message_utf8,
                    }));
                }
                other => {
                    if !self.confirm_sent.load(Ordering::SeqCst) {
                        return Err(ChannelError::NonConfirmed(MessageOnNonConfirmedChannel {
                            message: other,
                        }));
                    }
                    return Ok(other);
                }
            }
        }
    }

    pub async fn maybe_send_header(&self) -> Result<(), ChannelError> {
        let header = self.header.lock().unwrap().take();
        if let Some(header) = header {
            let mut send = self.send.lock().await;
            send.write_all(&header).await?;
        }
        Ok(())
    }

    pub async fn write_data(
        &self,
        data_buf: &[u8],
        data_type: SshDataType,
    ) -> Result<usize, ChannelError> {
        self.maybe_send_header().await?;

        let empty = DataOrExtendedDataMessage {
            data_type,
            data: Vec::new(),
        };
        let overhead = empty.encoded_len();
        let max_payload = self
            .info
            .max_packet_size
            .checked_sub(overhead as u64)
            .ok_or(ChannelError::MaxPacketSizeTooSmall {
                max_packet_size: self.info.max_packet_size,
                message_overhead: overhead,
            })? as usize;

        let mut written = 0;
        let mut send = self.send.lock().await;
        for chunk in data_buf.chunks(max_payload.max(1)) {
            let message = Message::Data(DataOrExtendedDataMessage {
                data_type,
                data: chunk.to_vec(),
            });
            let encoded = message.to_vec();
            send.write_all(&encoded).await?;
            written += encoded.len();
        }
        Ok(written)
    }

    pub async fn confirm_channel(&self, max_packet_size: u64) -> Result<(), ChannelError> {
        self.send_message(Message::ChannelOpenConfirmation(
            ChannelOpenConfirmationMessage { max_packet_size },
        ))
        .await?;
        self.confirm_sent.store(true, Ordering::SeqCst);
        Ok(())
    }

    pub async fn send_message(&self, message: Message) -> Result<(), ChannelError> {
        self.maybe_send_header().await?;
        let mut send = self.send.lock().await;
        send.write_all(&message.to_vec()).await?;
        Ok(())
    }

    pub async fn wait_add_datagram(&self, datagram: Vec<u8>) {
        let queue = self.datagrams_queue.read().unwrap().clone();
        queue.wait_add(datagram).await;
    }

    pub fn add_datagram(&self, datagram: Vec<u8>) -> bool {
        self.datagrams_queue.read().unwrap().add(datagram)
    }

    pub async fn receive_datagram(&self) -> Vec<u8> {
        let queue = self.datagrams_queue.read().unwrap().clone();
        queue.wait_next().await
    }

    pub async fn send_datagram(&self, datagram: Vec<u8>) -> Result<(), ChannelError> {
        self.maybe_send_header().await?;
        let sender = self.datagram_sender.read().unwrap().clone().ok_or(
            ChannelError::DatagramSenderMissing(SentDatagramOnNonDatagramChannel {
                channel_id: self.channel_id(),
            }),
        )?;
        sender.send(datagram).await?;
        Ok(())
    }

    pub async fn send_request(&self, request: ChannelRequestMessage) -> Result<(), ChannelError> {
        self.send_message(Message::ChannelRequest(request)).await
    }

    pub async fn cancel_read(&self) {
        self.recv.lock().await.cancel_read(42);
    }

    pub async fn close(&self) -> Result<(), ChannelError> {
        self.send.lock().await.close().await?;
        Ok(())
    }

    pub fn set_datagram_sender(&self, datagram_sender: Arc<ConversationDatagramSender>) {
        *self.datagram_sender.write().unwrap() = Some(datagram_sender);
    }

    pub fn set_datagram_queue(&self, queue: Arc<DatagramQueue>) {
        *self.datagrams_queue.write().unwrap() = queue;
    }
}

async fn parse_message(recv: &mut dyn ReceiveStream) -> Result<Message, ChannelError> {
    let message_type = read_var_int(recv).await?;
    Ok(match message_type {
        ssh3_proto::SSH_MSG_CHANNEL_REQUEST => {
            Message::ChannelRequest(read_channel_request(recv).await?)
        }
        ssh3_proto::SSH_MSG_CHANNEL_OPEN_CONFIRMATION => {
            Message::ChannelOpenConfirmation(ChannelOpenConfirmationMessage {
                max_packet_size: read_var_int(recv).await?,
            })
        }
        ssh3_proto::SSH_MSG_CHANNEL_OPEN_FAILURE => {
            Message::ChannelOpenFailure(ChannelOpenFailureMessage {
                reason_code: read_var_int(recv).await?,
                error_message_utf8: read_ssh_bytes(recv).await?,
                language_tag: read_ssh_bytes(recv).await?,
            })
        }
        ssh3_proto::SSH_MSG_CHANNEL_DATA => Message::Data(DataOrExtendedDataMessage {
            data_type: SSH_EXTENDED_DATA_NONE,
            data: read_ssh_bytes(recv).await?,
        }),
        ssh3_proto::SSH_MSG_CHANNEL_EXTENDED_DATA => Message::Data(DataOrExtendedDataMessage {
            data_type: read_var_int(recv).await?,
            data: read_ssh_bytes(recv).await?,
        }),
        kind => {
            return Err(ChannelError::Proto(ssh3_proto::Error::UnknownMessageType(
                kind,
            )));
        }
    })
}

async fn read_channel_request(
    recv: &mut dyn ReceiveStream,
) -> Result<ChannelRequestMessage, ChannelError> {
    let request_type = read_ssh_bytes(recv).await?;
    let want_reply = read_bool(recv).await?;
    let request = match request_type.as_slice() {
        b"pty-req" => ssh3_proto::ChannelRequest::Pty(ssh3_proto::PtyRequest {
            term: read_ssh_bytes(recv).await?,
            char_width: read_var_int(recv).await?,
            char_height: read_var_int(recv).await?,
            pixel_width: read_var_int(recv).await?,
            pixel_height: read_var_int(recv).await?,
            encoded_terminal_modes: read_ssh_bytes(recv).await?,
        }),
        b"x11-req" => ssh3_proto::ChannelRequest::X11(ssh3_proto::X11Request {
            single_connection: read_bool(recv).await?,
            x11_authentication_protocol: read_ssh_bytes(recv).await?,
            x11_authentication_cookie: read_ssh_bytes(recv).await?,
            x11_screen_number: read_var_int(recv).await?,
        }),
        b"shell" => ssh3_proto::ChannelRequest::Shell,
        b"exec" => ssh3_proto::ChannelRequest::Exec(ssh3_proto::ExecRequest {
            command: read_ssh_bytes(recv).await?,
        }),
        b"subsystem" => ssh3_proto::ChannelRequest::Subsystem(ssh3_proto::SubsystemRequest {
            subsystem_name: read_ssh_bytes(recv).await?,
        }),
        b"window-change" => {
            ssh3_proto::ChannelRequest::WindowChange(ssh3_proto::WindowChangeRequest {
                char_width: read_var_int(recv).await?,
                char_height: read_var_int(recv).await?,
                pixel_width: read_var_int(recv).await?,
                pixel_height: read_var_int(recv).await?,
            })
        }
        b"signal" => ssh3_proto::ChannelRequest::Signal(ssh3_proto::SignalRequest {
            signal_name_without_sig: read_ssh_bytes(recv).await?,
        }),
        b"exit-status" => ssh3_proto::ChannelRequest::ExitStatus(ssh3_proto::ExitStatusRequest {
            exit_status: read_var_int(recv).await?,
        }),
        b"exit-signal" => ssh3_proto::ChannelRequest::ExitSignal(ssh3_proto::ExitSignalRequest {
            signal_name_without_sig: read_ssh_bytes(recv).await?,
            core_dumped: read_bool(recv).await?,
            error_message_utf8: read_ssh_bytes(recv).await?,
            language_tag: read_ssh_bytes(recv).await?,
        }),
        b"forward-port" => {
            let protocol = ssh3_proto::ForwardingProtocol::try_from(read_var_int(recv).await?)?;
            let family = ssh3_proto::ForwardingAddressFamily::try_from(read_var_int(recv).await?)?;
            let mut octets = vec![
                0;
                match family {
                    ssh3_proto::ForwardingAddressFamily::Ipv4 => 4,
                    ssh3_proto::ForwardingAddressFamily::Ipv6 => 16,
                }
            ];
            recv.read_exact(&mut octets).await?;
            let mut port = [0; 2];
            recv.read_exact(&mut port).await?;
            ssh3_proto::ChannelRequest::ForwardPort(ssh3_proto::ForwardingRequest {
                protocol,
                ip_address: match family {
                    ssh3_proto::ForwardingAddressFamily::Ipv4 => std::net::IpAddr::V4(
                        std::net::Ipv4Addr::from(<[u8; 4]>::try_from(octets).unwrap()),
                    ),
                    ssh3_proto::ForwardingAddressFamily::Ipv6 => std::net::IpAddr::V6(
                        std::net::Ipv6Addr::from(<[u8; 16]>::try_from(octets).unwrap()),
                    ),
                },
                port: u16::from_be_bytes(port),
            })
        }
        _ => {
            return Err(ChannelError::Proto(ssh3_proto::Error::UnknownRequestType(
                request_type,
            )));
        }
    };
    Ok(ChannelRequestMessage {
        want_reply,
        request,
    })
}

async fn read_var_int(recv: &mut dyn ReceiveStream) -> Result<u64, ChannelError> {
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

async fn read_ssh_bytes(recv: &mut dyn ReceiveStream) -> Result<Vec<u8>, ChannelError> {
    let len = read_var_int(recv).await?;
    let len = usize::try_from(len)
        .map_err(|_| ChannelError::Proto(ssh3_proto::Error::InvalidLength(len)))?;
    let mut out = vec![0; len];
    recv.read_exact(&mut out).await?;
    Ok(out)
}

async fn read_bool(recv: &mut dyn ReceiveStream) -> Result<bool, ChannelError> {
    match read_byte(recv).await? {
        0 => Ok(false),
        1 => Ok(true),
        value => Err(ChannelError::Proto(ssh3_proto::Error::InvalidBool(value))),
    }
}

async fn read_byte(recv: &mut dyn ReceiveStream) -> Result<u8, ChannelError> {
    let mut byte = [0; 1];
    recv.read_exact(&mut byte).await?;
    Ok(byte[0])
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ssh3_proto::{
        ChannelHeader, ChannelRequest, ChannelRequestMessage, Message, SignalRequest,
        append_var_int,
    };

    use super::{Channel, ChannelError};
    use crate::conversation::ConversationDatagramSender;
    use crate::transport::testutil::{
        BytesReceiveStream, RecordingDatagramSender, RecordingSendStream,
    };

    fn conversation_id() -> [u8; 32] {
        [7; 32]
    }

    #[tokio::test]
    async fn write_data_sends_header_once_and_chunks_payload() {
        let (recv, _) = BytesReceiveStream::new(Vec::new());
        let (send, handle) = RecordingSendStream::new();
        let channel = Channel::new(
            11,
            conversation_id(),
            22,
            b"session".to_vec(),
            5,
            recv,
            send,
            None,
            true,
            true,
            true,
            4,
            None,
        );

        let written = channel
            .write_data(b"abcdefg", ssh3_proto::SSH_EXTENDED_DATA_NONE)
            .await
            .unwrap();
        let mut expected = ChannelHeader {
            conversation_stream_id: 11,
            channel_type: b"session".to_vec(),
            max_packet_size: 5,
        }
        .encode(None);
        let header_len = expected.len();
        for chunk in [
            b"ab".as_slice(),
            b"cd".as_slice(),
            b"ef".as_slice(),
            b"g".as_slice(),
        ] {
            expected.extend_from_slice(
                &Message::Data(ssh3_proto::DataOrExtendedDataMessage {
                    data_type: ssh3_proto::SSH_EXTENDED_DATA_NONE,
                    data: chunk.to_vec(),
                })
                .to_vec(),
            );
        }

        assert_eq!(written, expected.len() - header_len);
        assert_eq!(handle.bytes(), expected);
    }

    #[tokio::test]
    async fn next_message_handles_confirmation_then_returns_message() {
        let mut recv_bytes =
            Message::ChannelOpenConfirmation(ssh3_proto::ChannelOpenConfirmationMessage {
                max_packet_size: 4096,
            })
            .to_vec();
        recv_bytes.extend_from_slice(
            &Message::ChannelRequest(ChannelRequestMessage {
                want_reply: true,
                request: ChannelRequest::Signal(SignalRequest {
                    signal_name_without_sig: b"TERM".to_vec(),
                }),
            })
            .to_vec(),
        );

        let (recv, _) = BytesReceiveStream::new(recv_bytes);
        let (send, _) = RecordingSendStream::new();
        let channel = Channel::new(
            1,
            conversation_id(),
            2,
            b"session".to_vec(),
            1024,
            recv,
            send,
            None,
            false,
            true,
            false,
            4,
            None,
        );

        let message = channel.next_message().await.unwrap();
        assert!(channel.confirm_received());
        assert_eq!(
            message,
            Message::ChannelRequest(ChannelRequestMessage {
                want_reply: true,
                request: ChannelRequest::Signal(SignalRequest {
                    signal_name_without_sig: b"TERM".to_vec(),
                }),
            })
        );
    }

    #[tokio::test]
    async fn next_message_returns_non_confirmed_error() {
        let recv_bytes = Message::Data(ssh3_proto::DataOrExtendedDataMessage {
            data_type: ssh3_proto::SSH_EXTENDED_DATA_NONE,
            data: b"hello".to_vec(),
        })
        .to_vec();
        let (recv, _) = BytesReceiveStream::new(recv_bytes);
        let (send, _) = RecordingSendStream::new();
        let channel = Channel::new(
            1,
            conversation_id(),
            2,
            b"session".to_vec(),
            1024,
            recv,
            send,
            None,
            false,
            false,
            true,
            4,
            None,
        );

        match channel.next_message().await {
            Err(ChannelError::NonConfirmed(_)) => {}
            other => panic!("expected non-confirmed error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn send_datagram_uses_conversation_sender() {
        let sender = Arc::new(RecordingDatagramSender::default());
        let (recv, _) = BytesReceiveStream::new(Vec::new());
        let (send, _) = RecordingSendStream::new();
        let channel = Channel::new(
            11,
            conversation_id(),
            22,
            b"direct-udp".to_vec(),
            1024,
            recv,
            send,
            Some(Arc::new(ConversationDatagramSender::new(
                11,
                22,
                sender.clone(),
            ))),
            false,
            true,
            true,
            4,
            None,
        );

        channel.send_datagram(vec![9, 8, 7]).await.unwrap();

        let mut expected = Vec::new();
        append_var_int(&mut expected, 11);
        append_var_int(&mut expected, 22);
        expected.extend_from_slice(&[9, 8, 7]);
        assert_eq!(sender.datagrams(), vec![expected]);
    }
}
