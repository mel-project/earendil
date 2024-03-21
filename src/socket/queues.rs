use std::collections::HashMap;

use anyhow::Context;
use bytes::Bytes;


use earendil_packet::Dock;
use parking_lot::RwLock;
use smol::channel::{Receiver, Sender};

use crate::context::{CtxField, DaemonContext};

use super::{AnonEndpoint, RelayEndpoint};

pub struct QueueReceiver<T> {
    inner: Receiver<T>,
    _drop_fn: Box<dyn Fn() + Send + Sync + 'static>,
}

impl<T> QueueReceiver<T> {
    pub async fn recv(&self) -> Result<T, smol::channel::RecvError> {
        self.inner.recv().await
    }
}

impl<T> Drop for QueueReceiver<T> {
    fn drop(&mut self) {
        (self._drop_fn)();
    }
}

static RELAY_SOCKET_RECV_QUEUES: CtxField<RwLock<HashMap<Dock, Sender<(Bytes, AnonEndpoint)>>>> =
    |_| Default::default();

pub fn new_relay_queue(
    ctx: &DaemonContext,
    bind_to: Dock,
) -> anyhow::Result<QueueReceiver<(Bytes, AnonEndpoint)>> {
    let (send, recv) = smol::channel::bounded(1000);
    let mut queues = ctx.get(RELAY_SOCKET_RECV_QUEUES).write();
    if queues.contains_key(&bind_to) {
        anyhow::bail!("dock {bind_to} is occupied")
    }
    queues.insert(bind_to, send);
    let ctx = ctx.clone();
    Ok(QueueReceiver {
        inner: recv,
        _drop_fn: Box::new(move || {
            ctx.get(RELAY_SOCKET_RECV_QUEUES).write().remove(&bind_to);
        }),
    })
}

static CLIENT_SOCKET_RECV_QUEUES: CtxField<
    RwLock<HashMap<AnonEndpoint, Sender<(Bytes, RelayEndpoint)>>>,
> = |_| Default::default();

pub fn new_client_queue(
    ctx: &DaemonContext,
    bind_to: AnonEndpoint,
) -> anyhow::Result<QueueReceiver<(Bytes, RelayEndpoint)>> {
    let (send, recv) = smol::channel::bounded(1000);
    let mut queues = ctx.get(CLIENT_SOCKET_RECV_QUEUES).write();
    if queues.contains_key(&bind_to) {
        anyhow::bail!("endpoint {bind_to} is occupied")
    }
    queues.insert(bind_to, send);
    let ctx = ctx.clone();
    Ok(QueueReceiver {
        inner: recv,
        _drop_fn: Box::new(move || {
            ctx.get(CLIENT_SOCKET_RECV_QUEUES).write().remove(&bind_to);
        }),
    })
}

pub fn fwd_to_client_queue(
    ctx: &DaemonContext,
    msg: Bytes,
    from: RelayEndpoint,
    to: AnonEndpoint,
) -> anyhow::Result<()> {
    let queues = ctx.get(CLIENT_SOCKET_RECV_QUEUES).read();
    let send_to = queues
        .get(&to)
        .context(format!("cannot find socket bound to {to} among {:?}", queues.keys().collect::<Vec<_>>()))?;
    let _ = send_to.try_send((msg, from));
    Ok(())
}

pub fn fwd_to_relay_queue(
    ctx: &DaemonContext,
    msg: Bytes,
    from: AnonEndpoint,
    to: Dock,
) -> anyhow::Result<()> {
    let queues = ctx.get(RELAY_SOCKET_RECV_QUEUES).read();
    let send_to = queues
        .get(&to)
        .context(format!("cannot find socket bound to {to}"))?;
    let _ = send_to.try_send((msg, from));
    Ok(())
}
