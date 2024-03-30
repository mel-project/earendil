use bytes::Bytes;

use parking_lot::Mutex;
use recycle_box::{coerce_box, RecycleBox};
use serde::{Deserialize, Serialize};
use smol::prelude::*;

use std::{
    collections::VecDeque,
    io::{Read, Write},
    pin::Pin,
    sync::Arc,
    task::Context,
    task::Poll,
};

mod inflight;
mod reorderer;
pub mod stream_state;

/// [Stream] represents a reliable stream. It implements [AsyncRead], [AsyncWrite], and [Clone], making using it very similar to using a TcpStream.
pub struct Stream {
    // forces the multiplex to tick immediately
    tick_notify: Arc<dyn Fn() + Send + Sync + 'static>,
    // a future that resolves when read can return some bytes
    read_ready_future: Option<Pin<RecycleBox<dyn Future<Output = ()> + Send + 'static>>>,
    read_ready_resolved: bool,
    // a future that resolves when there's room to write more bytes
    write_ready_future: Option<Pin<RecycleBox<dyn Future<Output = ()> + Send + 'static>>>,
    write_ready_resolved: bool,
    // an event that fires when write or read *might* unblock
    local_notify: Arc<async_event::Event>,
    // queues that connect this facade with the "real deal" in Multiplex
    queues: Arc<Mutex<StreamQueues>>,
}

impl Drop for Stream {
    fn drop(&mut self) {
        if Arc::strong_count(&self.local_notify) <= 1 {
            // this means we're the last one!
            self.queues.lock().closed = true;
            (self.tick_notify)();
        }
    }
}

/// SAFETY: because of the definition of AsyncRead, it's not possible to ever concurrently end up polling the futures in the RecycleBoxes.
unsafe impl Sync for Stream {}

// Note: a Stream can be thought of as a *facade* to a particular StreamState in the Multiplex.
impl Stream {
    fn new(
        tick_notify: impl Fn() + Send + Sync + 'static,
        ready: Arc<async_event::Event>,
        queues: Arc<Mutex<StreamQueues>>,
    ) -> Self {
        Self {
            tick_notify: Arc::new(tick_notify),
            read_ready_future: Some(RecycleBox::into_pin(coerce_box!(RecycleBox::new(async {
                smol::future::pending().await
            })))),
            read_ready_resolved: true, // forces redoing the future on first read
            write_ready_future: Some(RecycleBox::into_pin(coerce_box!(RecycleBox::new(async {
                smol::future::pending().await
            })))),
            write_ready_resolved: true, // forces redoing the future on first write
            local_notify: ready,

            queues,
        }
    }

    /// Waits until this Stream is fully connected.
    pub async fn wait_connected(&self) -> std::io::Result<()> {
        self.local_notify
            .wait_until(|| {
                log::trace!("waiting until connected...");
                if self.queues.lock().connected {
                    log::trace!("connected now");
                    Some(())
                } else {
                    None
                }
            })
            .await;
        Ok(())
    }

    /// Shuts down the stream, causing future read and write operations to fail.
    pub async fn shutdown(&mut self) {
        self.queues.lock().closed = true;
        (self.tick_notify)();
        self.local_notify.notify_all();
    }
}

impl Clone for Stream {
    fn clone(&self) -> Self {
        let tn = self.tick_notify.clone();
        Self::new(move || tn(), self.local_notify.clone(), self.queues.clone())
    }
}

impl AsyncRead for Stream {
    /// We use this horrible hack because we cannot simply write `async fn read()`. AsyncRead is defined in this arcane fashion largely because Rust does not have async traits yet.
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut read_future = self.read_ready_future.take().unwrap();
        // if resolved, then reset
        if self.read_ready_resolved {
            let read_ready = self.local_notify.clone();
            let inner = self.queues.clone();
            read_future = RecycleBox::into_pin(coerce_box!(RecycleBox::recycle_pinned(
                read_future,
                async move {
                    read_ready
                        .wait_until(move || {
                            let mut inner = inner.lock();

                            if inner.read_stream.capacity() > inner.read_stream.len() * 2 {
                                inner.read_stream.shrink_to_fit();
                            }
                            if !inner.read_stream.is_empty() || inner.closed {
                                Some(())
                            } else {
                                None
                            }
                        })
                        .await
                }
            )));
        }
        // poll the recycle-boxed futures
        match read_future.poll(cx) {
            Poll::Ready(()) => {
                self.read_ready_resolved = true;
                self.read_ready_future = Some(read_future);
                let mut queues = self.queues.lock();
                let n = queues.read_stream.read(buf);
                (self.tick_notify)();

                Poll::Ready(n)
            }
            Poll::Pending => {
                self.read_ready_resolved = false;
                self.read_ready_future = Some(read_future);
                Poll::Pending
            }
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut write_future = self.write_ready_future.take().unwrap();
        // if resolved, then reset
        if self.write_ready_resolved {
            let write_ready = self.local_notify.clone();
            let inner = self.queues.clone();
            // this waits until there's less than 100 KB waiting to be written. this produces the right backpressure
            write_future = RecycleBox::into_pin(coerce_box!(RecycleBox::recycle_pinned(
                write_future,
                async move {
                    write_ready
                        .wait_until(move || {
                            let mut inner = inner.lock();
                            if inner.write_stream.capacity() > inner.write_stream.len() * 2 {
                                inner.write_stream.shrink_to_fit();
                            }
                            if inner.write_stream.len() <= 100_000 {
                                Some(())
                            } else {
                                None
                            }
                        })
                        .await
                }
            )));
        }
        // poll the recycle-boxed futures
        match write_future.poll(cx) {
            Poll::Ready(()) => {
                self.write_ready_resolved = true;
                self.write_ready_future = Some(write_future);
                let n = self.queues.lock().write_stream.write(buf);
                (self.tick_notify)();

                Poll::Ready(n)
            }
            Poll::Pending => {
                self.write_ready_resolved = false;
                self.write_ready_future = Some(write_future);
                Poll::Pending
            }
        }
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.queues.lock().closed = true;
        (self.tick_notify)();
        Poll::Ready(Ok(()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[derive(Default)]
/// The "go-between" between MuxStream and StreamState
struct StreamQueues {
    /// Bytes from the other end, waiting to be read from the stream
    read_stream: VecDeque<u8>,
    /// Bytes to be sent to the other end, waiting to be written to the stream
    write_stream: VecDeque<u8>,

    connected: bool,
    closed: bool,
}

/// A stream-related message.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum StreamMessage {
    Reliable {
        kind: RelKind,
        seqno: u64,
        payload: Bytes,
    },

    Empty,
}

impl StreamMessage {
    pub fn seqno(&self) -> u64 {
        match self {
            StreamMessage::Reliable {
                kind: _,
                seqno,
                payload: _,
            } => *seqno,
            _ => 0,
        }
    }
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub enum RelKind {
    Syn,
    SynAck,
    Data,
    DataAck,
    Fin,
    FinAck,
    Rst,
}
