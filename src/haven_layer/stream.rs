use std::{pin::Pin, sync::Arc};

use clone_macro::clone;
use futures_util::{AsyncRead, AsyncWrite};
use parking_lot::Mutex;
use smol::{future::FutureExt, Task, Timer};
use stdcode::StdcodeSerializeExt;
use virta::{stream_state::StreamState, StreamMessage};

use super::HavenPacketConn;

#[derive(Clone)]
/// A reliable, TCP-like stream for visitor-haven communication.
///
/// Streams, like their underlying packet connections, have a very high degree of anonymity. Each stream is unlinkable with other streams, including streams by the same visitor, to both Earendil infrastructure and the destination haven. In exchange, creating and maintaining a stream is relatively expensive --- significantly more so than a TCP connection.
///
/// For most applications where a single identified user opens many connection, such as HTTP or proxying, using a stream to represent an application-level connection is inefficient. Using some form of one-to-many multiplexing is strongly recommended.
///
/// In fact, the de-facto standard protocol used in Earendil to represent TCP channels is [picomux] over [HavenStream]s. The convenience wrappers [crate::PooledListener] and [crate::PooledVisitor] are provided for that.
pub struct HeavyStream {
    inner_stream: virta::Stream,
    _task: Arc<Task<()>>,
}

impl HeavyStream {
    /// Creates a reliable stream from the underlying packet connection.
    pub fn new(underlying: HavenPacketConn) -> Self {
        let underlying = Arc::new(underlying);
        let (send_tick, recv_tick) = smol::channel::unbounded::<()>();
        let (send_outgoing, recv_outgoing) = smol::channel::unbounded::<StreamMessage>();
        let tick_notify = move || {
            if let Err(e) = send_tick.try_send(()) {
                tracing::debug!("Stream send_tick.try_send(()) failed! {e}");
            }
        };
        let outgoing_callback = move |smsg: StreamMessage| {
            if let Err(e) = send_outgoing.try_send(smsg) {
                tracing::debug!("Stream outgoing_callback.try_send(()) failed! {e}");
            }
        };

        let (s2_state, s2_stream) = StreamState::new_established(tick_notify);

        let wrapped_ss = Arc::new(Mutex::new(s2_state));
        let ticker_task = clone!([wrapped_ss], async move {
            loop {
                let maybe = wrapped_ss.lock().tick(&outgoing_callback);
                if let Some(retick_time) = maybe {
                    let retick_timer = async {
                        Timer::at(retick_time).await;
                        Ok(())
                    };
                    recv_tick.recv().race(retick_timer).await?;
                } else {
                    // stream died; returning
                    return anyhow::Ok(());
                };
            }
        });

        let forward_task = clone!([wrapped_ss, underlying], async move {
            let up_loop = async {
                loop {
                    let smsg = recv_outgoing.recv().await?;
                    underlying.send_pkt(&smsg.stdcode()).await?;
                }
            };
            let down_loop = async {
                loop {
                    let msg = underlying.recv_pkt().await?;
                    let smsg: StreamMessage = stdcode::deserialize(&msg)?;
                    wrapped_ss.lock().inject_incoming(smsg);
                }
            };
            up_loop.race(down_loop).await
        });

        let task = smolscale::spawn(async {
            if let Err(e) = ticker_task.race(forward_task).await {
                tracing::debug!("a stream task failed: {e}")
            }
        });

        Self {
            inner_stream: s2_stream,
            _task: Arc::new(task),
        }
    }

    fn pin_project_inner(self: std::pin::Pin<&mut Self>) -> Pin<&mut virta::Stream> {
        // SAFETY: this is a safe pin-projection, since we never get a &mut sosistab2::Stream from a Pin<&mut Stream> elsewhere.
        // Safety requires that we either consistently lose Pin or keep it.
        // We could use the "pin_project" crate but I'm too lazy.
        unsafe { self.map_unchecked_mut(|s| &mut s.inner_stream) }
    }
}

impl AsyncRead for HeavyStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let inner = self.pin_project_inner();
        inner.poll_read(cx, buf)
    }
}

impl AsyncWrite for HeavyStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let inner = self.pin_project_inner();
        inner.poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let inner = self.pin_project_inner();
        inner.poll_flush(cx)
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let inner = self.pin_project_inner();
        inner.poll_close(cx)
    }
}
