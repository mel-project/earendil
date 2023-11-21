use std::sync::Arc;

use earendil::socket::Endpoint;
use futures_util::{AsyncRead, AsyncWrite};
use parking_lot::Mutex;
use smol::Task;
use sosistab2::StreamState;

pub struct Stream {
    stream_state: Arc<Mutex<StreamState>>,
    _task: Task<()>,
}

impl Stream {
    pub async fn connect(socket: Socket, server_ep: Endpoint) -> anyhow::Result<Self> {
        todo!()
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        todo!()
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        todo!()
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        todo!()
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        todo!()
    }
}
