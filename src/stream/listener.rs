use std::sync::Arc;

use dashmap::DashMap;
use futures_util::{future, FutureExt};
use parking_lot::Mutex;
use sosistab2::{RelKind, StreamMessage, StreamState};
use stdcode::StdcodeSerializeExt;

use crate::socket::{Endpoint, Socket};

use super::Stream;

pub struct StreamListener {
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
            let (msg, client_ep) = self.socket.recv_from().await?;
            let stream_msg: StreamMessage = stdcode::deserialize(&msg)?;
            log::trace!("we got msg {:?}", stream_msg);
            match stream_msg.clone() {
                StreamMessage::Reliable {
                    kind: RelKind::Syn,
                    stream_id,
                    seqno,
                    payload,
                } => {
                    let (send_tick, recv_tick) = smol::channel::unbounded();

                    let tick_notify = move || {
                        if let Err(e) = send_tick.try_send(()) {
                            log::debug!("StreamListener send_tick.try_send(()) failed! {e}");
                        }
                    };
                    let (s2_state, s2_stream) =
                        StreamState::new_established(tick_notify, stream_id, "".into());
                    let s2_state = Arc::new(Mutex::new(s2_state));

                    let syn_ack = StreamMessage::Reliable {
                        kind: sosistab2::RelKind::SynAck,
                        stream_id,
                        seqno,
                        payload,
                    };

                    // send the SYNACK message
                    self.socket
                        .send_to(syn_ack.stdcode().into(), client_ep)
                        .await?;

                    let state = s2_state.clone();
                    let skt = self.socket.clone();
                    let table = self.table.clone();
                    let ticker = smolscale::spawn(async move {
                        loop {
                            let mut outgoing = Vec::new();
                            log::debug!("listener-spawned ticker ticking!!");
                            let maybe_retick = state.lock().tick(|msg| outgoing.push(msg));

                            if let Some(retick_time) = maybe_retick {
                                let timer = smol::Timer::at(retick_time);
                                let recv_future = recv_tick.recv();
                                future::select(recv_future, timer.fuse()).await;
                                for msg in outgoing.drain(..) {
                                    log::debug!("listener sending back result of tick {:?}", msg);
                                    let msg = msg.stdcode().into();
                                    let _ = skt.send_to(msg, client_ep).await;
                                }
                            } else {
                                log::warn!("no retick time: connection is dead! dropping from the table...");
                                table.remove(&client_ep);
                                return;
                            }
                        }
                    });

                    // insert state into table
                    self.table.insert(client_ep, s2_state);

                    // return a Stream
                    return Ok(Stream {
                        inner_stream: s2_stream,
                        _task: ticker,
                    });
                }

                StreamMessage::Reliable {
                    kind: RelKind::Rst,
                    stream_id: _,
                    seqno: _,
                    payload: _,
                } => {
                    self.table.remove(&client_ep);
                    continue;
                }

                StreamMessage::Reliable {
                    kind: _,
                    stream_id,
                    seqno,
                    payload,
                } => match self.table.get(&client_ep) {
                    Some(state) => {
                        log::debug!("INJECTING into state: {:?}", stream_msg);
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
                        let msg = rst_msg.stdcode().into();
                        self.socket.send_to(msg, client_ep).await?;

                        continue;
                    }
                },
                _ => {
                    log::warn!("unreliable stream messages aren't supported")
                }
            };
        }
    }
}
