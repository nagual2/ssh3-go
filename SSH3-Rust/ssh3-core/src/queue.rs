use std::collections::VecDeque;
use std::sync::Mutex;

use tokio::sync::Notify;

pub struct AcceptQueue<T> {
    queue: Mutex<VecDeque<T>>,
    notify: Notify,
}

impl<T> AcceptQueue<T> {
    pub fn new() -> Self {
        Self {
            queue: Mutex::new(VecDeque::new()),
            notify: Notify::new(),
        }
    }

    pub fn add(&self, item: T) {
        self.queue.lock().unwrap().push_back(item);
        self.notify.notify_one();
    }

    pub fn next(&self) -> Option<T> {
        self.queue.lock().unwrap().pop_front()
    }

    pub async fn wait_next(&self) -> T {
        loop {
            let notified = self.notify.notified();
            if let Some(item) = self.next() {
                return item;
            }
            notified.await;
        }
    }
}

impl<T> Default for AcceptQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

pub struct DatagramQueue {
    queue: Mutex<VecDeque<Vec<u8>>>,
    capacity: usize,
    not_empty: Notify,
    not_full: Notify,
}

impl DatagramQueue {
    pub fn new(capacity: usize) -> Self {
        Self {
            queue: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
            not_empty: Notify::new(),
            not_full: Notify::new(),
        }
    }

    pub fn add(&self, datagram: Vec<u8>) -> bool {
        let mut queue = self.queue.lock().unwrap();
        if queue.len() >= self.capacity {
            return false;
        }
        queue.push_back(datagram);
        drop(queue);
        self.not_empty.notify_one();
        true
    }

    pub async fn wait_add(&self, datagram: Vec<u8>) {
        let mut datagram = Some(datagram);
        loop {
            let notified = self.not_full.notified();
            {
                let mut queue = self.queue.lock().unwrap();
                if queue.len() < self.capacity {
                    queue.push_back(datagram.take().unwrap());
                    drop(queue);
                    self.not_empty.notify_one();
                    return;
                }
            }
            notified.await;
        }
    }

    pub fn next(&self) -> Option<Vec<u8>> {
        let datagram = self.queue.lock().unwrap().pop_front();
        if datagram.is_some() {
            self.not_full.notify_one();
        }
        datagram
    }

    pub async fn wait_next(&self) -> Vec<u8> {
        loop {
            let notified = self.not_empty.notified();
            if let Some(datagram) = self.next() {
                return datagram;
            }
            notified.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AcceptQueue, DatagramQueue};

    #[tokio::test]
    async fn accept_queue_delivers_items_in_order() {
        let queue = AcceptQueue::new();
        queue.add(1);
        queue.add(2);

        assert_eq!(queue.next(), Some(1));
        assert_eq!(queue.wait_next().await, 2);
    }

    #[tokio::test]
    async fn datagram_queue_blocks_until_space_and_preserves_order() {
        let queue = DatagramQueue::new(1);
        assert!(queue.add(vec![1]));
        assert!(!queue.add(vec![2]));

        let waiting = queue.wait_add(vec![2]);
        tokio::pin!(waiting);
        tokio::task::yield_now().await;
        assert_eq!(queue.wait_next().await, vec![1]);
        waiting.await;
        assert_eq!(queue.wait_next().await, vec![2]);
    }
}
