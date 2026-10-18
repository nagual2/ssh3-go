use std::io;

use async_trait::async_trait;

#[async_trait]
pub trait ReceiveStream: Send {
    async fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()>;
    fn cancel_read(&mut self, error_code: u64);
}

#[async_trait]
pub trait SendStream: Send {
    async fn write_all(&mut self, buf: &[u8]) -> io::Result<()>;
    async fn close(&mut self) -> io::Result<()>;
}

#[async_trait]
pub trait DatagramSender: Send + Sync {
    async fn send_datagram(&self, datagram: Vec<u8>) -> io::Result<()>;
}

#[cfg(test)]
pub mod testutil {
    use std::io::{self, Cursor, Read};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;

    use super::{DatagramSender, ReceiveStream, SendStream};

    #[derive(Clone)]
    pub struct BytesReceiveHandle {
        cancelled: Arc<Mutex<Vec<u64>>>,
    }

    impl BytesReceiveHandle {
        pub fn cancelled_codes(&self) -> Vec<u64> {
            self.cancelled.lock().unwrap().clone()
        }
    }

    pub struct BytesReceiveStream {
        inner: Cursor<Vec<u8>>,
        cancelled: Arc<Mutex<Vec<u64>>>,
    }

    impl BytesReceiveStream {
        pub fn new(bytes: Vec<u8>) -> (Self, BytesReceiveHandle) {
            let cancelled = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    inner: Cursor::new(bytes),
                    cancelled: cancelled.clone(),
                },
                BytesReceiveHandle { cancelled },
            )
        }
    }

    #[async_trait]
    impl ReceiveStream for BytesReceiveStream {
        async fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
            self.inner.read_exact(buf)
        }

        fn cancel_read(&mut self, error_code: u64) {
            self.cancelled.lock().unwrap().push(error_code);
        }
    }

    #[derive(Clone)]
    pub struct RecordingSendHandle {
        bytes: Arc<Mutex<Vec<u8>>>,
        closed: Arc<AtomicBool>,
    }

    impl RecordingSendHandle {
        pub fn bytes(&self) -> Vec<u8> {
            self.bytes.lock().unwrap().clone()
        }

        pub fn is_closed(&self) -> bool {
            self.closed.load(Ordering::SeqCst)
        }
    }

    pub struct RecordingSendStream {
        bytes: Arc<Mutex<Vec<u8>>>,
        closed: Arc<AtomicBool>,
    }

    impl RecordingSendStream {
        pub fn new() -> (Self, RecordingSendHandle) {
            let bytes = Arc::new(Mutex::new(Vec::new()));
            let closed = Arc::new(AtomicBool::new(false));
            (
                Self {
                    bytes: bytes.clone(),
                    closed: closed.clone(),
                },
                RecordingSendHandle { bytes, closed },
            )
        }
    }

    #[async_trait]
    impl SendStream for RecordingSendStream {
        async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
            self.bytes.lock().unwrap().extend_from_slice(buf);
            Ok(())
        }

        async fn close(&mut self) -> io::Result<()> {
            self.closed.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    #[derive(Clone, Default)]
    pub struct RecordingDatagramSender {
        datagrams: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl RecordingDatagramSender {
        pub fn datagrams(&self) -> Vec<Vec<u8>> {
            self.datagrams.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl DatagramSender for RecordingDatagramSender {
        async fn send_datagram(&self, datagram: Vec<u8>) -> io::Result<()> {
            self.datagrams.lock().unwrap().push(datagram);
            Ok(())
        }
    }
}
