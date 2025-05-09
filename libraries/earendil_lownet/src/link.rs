use async_stdcode::{StdcodeReader, StdcodeWriter};
use futures_concurrency::future::Race;
use futures_util::AsyncReadExt;
use haiyuu::{Process, WeakHandle};

use crate::{Datagram, router::Router};

pub struct Link {
    pub pipe: Box<dyn sillad::Pipe>,
    pub router: WeakHandle<Router>,
    pub on_drop: Box<dyn FnMut() + Send + 'static>,
}

impl Drop for Link {
    fn drop(&mut self) {
        (self.on_drop)()
    }
}

impl Process for Link {
    type Message = Datagram;
    type Output = ();
    const MAILBOX_CAP: usize = 100;

    async fn run(&mut self, mailbox: &mut haiyuu::Mailbox<Self>) -> Self::Output {
        let (read, write) = (&mut self.pipe).split();
        let (mut read, mut write) = (StdcodeReader::new(read), StdcodeWriter::new(write));
        let read_loop = async {
            loop {
                let dg: Datagram = read.read().await?;
                self.router.send(dg).await?;
            }
        };
        let write_loop = async {
            loop {
                let dg = mailbox.recv().await;
                write.write(dg).await?;
            }
        };
        let res: anyhow::Result<()> = (read_loop, write_loop).race().await;
        if let Err(err) = res {
            tracing::debug!(err = debug(err), "link died")
        }
    }
}
