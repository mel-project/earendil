use std::sync::Arc;

use bytes::Bytes;
use dashmap::DashMap;
use earendil::socket::{Endpoint, Socket};
use futures_util::{future, FutureExt};
use parking_lot::Mutex;
use sosistab2::{RelKind, StreamMessage, StreamState};
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
                    match stream_msg.clone() {
                        StreamMessage::Reliable {
                            kind,
                            stream_id,
                            seqno,
                            payload,
                        } => {
                            match kind {
                                RelKind::Syn => {
                                    let (send_tick, recv_tick) = smol::channel::unbounded();

                                    let tick_notify = move || {
                                        let _ = send_tick.try_send(());
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
                                        inner_stream: s2_stream,
                                        _task: ticker,
                                    }
                                }

                                RelKind::Rst => {
                                    self.table.remove(&endpoint);
                                    continue;
                                }

                                _ => match self.table.get(&endpoint) {
                                    Some(state) => {
                                        state.lock().inject_incoming(stream_msg);
                                        continue;
                                    }
                                    None => {
                                        let rst_msg = StreamMessage::Reliable {
                                            kind: RelKind::Rst,
                                            stream_id,
                                            seqno,
                                            payload,
                                        };
                                        let msg = Bytes::copy_from_slice(&rst_msg.stdcode());
                                        self.socket.send_to(msg, endpoint).await?;

                                        continue;
                                    }
                                },
                            };
                        }
                        _ => log::warn!("unreliable stream messages aren't supported"),
                    }
                }
                Err(e) => {
                    log::warn!("error while receiving stream packet: {:?}", e);
                }
            }
        }
    }
}
