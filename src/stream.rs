use std::{pin::Pin, sync::Arc, time::Duration};

use bytes::Bytes;
use clone_macro::clone;
use futures_util::{AsyncRead, AsyncWrite};
use parking_lot::Mutex;
use smol::{future::FutureExt, Task, Timer};
use sosistab2::{RelKind, StreamMessage, StreamState};
use stdcode::StdcodeSerializeExt;

use crate::haven::HavenConnection;

#[derive(Clone)]
pub struct Stream {
    inner_stream: sosistab2::Stream,
    _task: Arc<Task<()>>,
}

impl Stream {
    pub fn new(underlying: HavenConnection) -> Self {
        todo!()
    }

    // #[tracing::instrument(skip(socket))]
    // pub async fn connect(socket: Socket, server_endpoint: Endpoint) -> anyhow::Result<Self> {
    //     // handshake
    //     let our_stream_id: u16 = rand::random();
    //     let syn = StreamMessage::Reliable {
    //         kind: RelKind::Syn,
    //         stream_id: our_stream_id,
    //         seqno: 0,
    //         payload: Bytes::new(),
    //     };
    //     let mut timeout = 4;
    //     let send_syn = async {
    //         loop {
    //             tracing::trace!("sending SYN");
    //             socket
    //                 .send_to(syn.stdcode().into(), server_endpoint)
    //                 .await?;
    //             Timer::after(Duration::from_secs(timeout)).await;
    //             timeout *= 2;
    //         }
    //     };
    //     let wait_synack = async {
    //         loop {
    //             let (msg, ep) = socket.recv_from().await?;
    //             if ep == server_endpoint {
    //                 let maybe: Result<StreamMessage, _> = stdcode::deserialize(&msg);

    //                 if let Ok(StreamMessage::Reliable {
    //                     kind: RelKind::SynAck,
    //                     stream_id: _our_stream_id,
    //                     seqno: _,
    //                     payload: _,
    //                 }) = maybe
    //                 {
    //                     break anyhow::Ok(());
    //                 }
    //             };
    //         }
    //     };
    //     send_syn.race(wait_synack).await?;
    //     tracing::trace!("received SYNACK");

    //     // construct sosistab2::Stream & sosistab2::StreamStates
    //     let (send_tick, recv_tick) = smol::channel::unbounded::<()>();
    //     let (send_outgoing, recv_outgoing) = smol::channel::unbounded::<StreamMessage>();
    //     let tick_notify = move || {
    //         if let Err(e) = send_tick.try_send(()) {
    //             tracing::debug!("Stream send_tick.try_send(()) failed! {e}");
    //         }
    //     };
    //     let outgoing_callback = move |smsg: StreamMessage| {
    //         if let Err(e) = send_outgoing.try_send(smsg) {
    //             tracing::debug!("Stream outgoing_callback.try_send(()) failed! {e}");
    //         }
    //     };

    //     let (s2_state, s2_stream) =
    //         StreamState::new_established(tick_notify, our_stream_id, "".to_owned());

    //     let wrapped_ss = Arc::new(Mutex::new(s2_state));
    //     let ticker_task = clone!([wrapped_ss], async move {
    //         loop {
    //             let maybe = wrapped_ss.lock().tick(&outgoing_callback);
    //             if let Some(retick_time) = maybe {
    //                 let retick_timer = async {
    //                     Timer::at(retick_time).await;
    //                     Ok(())
    //                 };
    //                 recv_tick.recv().race(retick_timer).await?;
    //             } else {
    //                 // stream died; returning
    //                 return anyhow::Ok(());
    //             };
    //         }
    //     });

    //     let forward_task = clone!([wrapped_ss], async move {
    //         let up_loop = async {
    //             loop {
    //                 let smsg = recv_outgoing.recv().await?;
    //                 socket
    //                     .send_to(smsg.stdcode().into(), server_endpoint)
    //                     .await?;
    //             }
    //         };
    //         let down_loop = async {
    //             loop {
    //                 let (msg, _ep) = socket.recv_from().await?;
    //                 let smsg: StreamMessage = stdcode::deserialize(&msg)?;
    //                 wrapped_ss.lock().inject_incoming(smsg);
    //             }
    //         };
    //         up_loop.race(down_loop).await
    //     });

    //     let task = smolscale::spawn(async {
    //         if let Err(e) = ticker_task.race(forward_task).await {
    //             tracing::debug!("a stream task failed: {e}")
    //         }
    //     });

    //     Ok(Self {
    //         inner_stream: s2_stream,
    //         _task: Arc::new(task),
    //     })
    // }

    fn pin_project_inner(self: std::pin::Pin<&mut Self>) -> Pin<&mut sosistab2::Stream> {
        // SAFETY: this is a safe pin-projection, since we never get a &mut sosistab2::Stream from a Pin<&mut Stream> elsewhere.
        // Safety requires that we either consistently lose Pin or keep it.
        // We could use the "pin_project" crate but I'm too lazy.
        unsafe { self.map_unchecked_mut(|s| &mut s.inner_stream) }
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let inner = self.pin_project_inner();
        inner.poll_read(cx, buf)
    }
}

impl AsyncWrite for Stream {
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
