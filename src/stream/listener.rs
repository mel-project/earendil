use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::Bytes;
use dashmap::DashMap;
use earendil::socket::{Endpoint, Socket};
use futures_util::{future, FutureExt};
use parking_lot::Mutex;
use smol::{channel::Sender, Timer};
use sosistab2::{StreamMessage, StreamState};
use stdcode::StdcodeSerializeExt;

use super::Stream;

struct StreamListener {
    socket: Arc<Socket>,
    table: Arc<DashMap<Endpoint, Arc<Mutex<sosistab2::StreamState>>>>,
}

impl StreamListener {
    pub fn listen(socket: Socket) -> StreamListener {
        Self {
            socket: Arc::new(socket),
            table: Arc::new(DashMap::new()),
        }
    }

    pub async fn accept(&mut self) -> anyhow::Result<Stream> {
        loop {
            match self.socket.recv_from().await {
                Ok((msg, endpoint)) => {
                    let stream_msg: StreamMessage = stdcode::deserialize(&msg)?;
                    match stream_msg {
                        StreamMessage::Reliable {
                            kind,
                            stream_id,
                            seqno,
                            payload,
                        } => {
                            match kind {
                                sosistab2::RelKind::Syn => {
                                    let (send_tick, recv_tick) = smol::channel::unbounded();

                                    let tick_notify = move || {
                                        let send_tick = send_tick.clone();
                                        smolscale::spawn(async move {
                                            let _ = send_tick.send(()).await;
                                        })
                                        .detach();
                                    };
                                    let (s2_state, s2_stream) = StreamState::new_established(
                                        tick_notify,
                                        stream_id,
                                        "".into(),
                                    );
                                    let s2_state = Arc::new(Mutex::new(s2_state));

                                    let syn_ack = StreamMessage::Reliable {
                                        kind: sosistab2::RelKind::SynAck,
                                        stream_id,
                                        seqno,
                                        payload,
                                    };

                                    // send the SYNACK message
                                    self.socket
                                        .send_to(
                                            Bytes::copy_from_slice(&syn_ack.stdcode()),
                                            endpoint,
                                        )
                                        .await?;

                                    let state = s2_state.clone();
                                    let skt = self.socket.clone();
                                    let table = self.table.clone();
                                    let ticker = smolscale::spawn(async move {
                                        let mut outgoing = Vec::new();
                                        let maybe_retick =
                                            state.lock().tick(|msg| outgoing.push(msg));

                                        if let Some(retick_time) = maybe_retick {
                                            let timer = smol::Timer::at(retick_time);
                                            let recv_future = recv_tick.recv();

                                            future::select(recv_future, timer.fuse()).await;
                                            for msg in outgoing.drain(..) {
                                                let msg = Bytes::copy_from_slice(&msg.stdcode());
                                                let _ = skt.send_to(msg, endpoint).await;
                                            }
                                        } else {
                                            log::warn!("no retick time: connection is dead! dropping from the table...");
                                            table.remove(&endpoint);
                                        }
                                    });

                                    // insert state into table
                                    self.table.insert(endpoint, s2_state);

                                    // return a Stream
                                    Stream {
                                        s2_stream: Arc::new(Mutex::new(s2_stream)),
                                        ticker,
                                    }
                                }

                                // TODO: handle non-SYN messages
                                _ => todo!(),
                            };
                        }
                        _ => log::warn!("unreliable stream messages aren't supported"),
                    }
                }
                Err(e) => {
                    log::warn!("error while receiving packet");
                }
            }
        }
    }
}
