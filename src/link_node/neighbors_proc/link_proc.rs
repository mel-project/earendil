use super::{NeighborMessage, NeighborProcess};

use bytes::Bytes;
use earendil_crypt::{ClientId, RelayFingerprint};

use futures_util::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use haiyuu::Handle;
use smol::future::FutureExt as _;

pub struct LinkProcess {
    parent: Handle<NeighborProcess>,
    remote: either::Either<RelayFingerprint, ClientId>,

    pipe: Box<dyn sillad::Pipe>,
}

impl haiyuu::Process for LinkProcess {
    type Message = Bytes;
    type Output = ();
    const MAILBOX_CAP: usize = 100;

    async fn run(&mut self, mailbox: &mut haiyuu::Mailbox<Self>) -> Self::Output {
        let (mut read_pipe, mut write_pipe) = (&mut self.pipe).split();
        let upload_loop = async {
            loop {
                let msg = mailbox.recv().await;
                write_pascal(&msg, &mut write_pipe).await?;
            }
        };

        let download_loop = async {
            loop {
                let msg = read_pascal(&mut read_pipe).await?;

                match self.remote {
                    either::Either::Left(relay) => {
                        self.parent
                            .send(NeighborMessage::FromRelay(msg.into(), relay))
                            .await?;
                    }
                    either::Either::Right(_) => todo!(),
                }
            }
        };
        let result: anyhow::Result<()> = upload_loop.race(download_loop).await;
        if let Err(err) = result {
            tracing::warn!(
                remote = debug(self.remote),
                err = debug(err),
                "link process stopped"
            );
        }
    }
}

async fn write_pascal<W: AsyncWrite + Unpin>(message: &[u8], mut out: W) -> anyhow::Result<()> {
    let len = (message.len() as u32).to_be_bytes();

    out.write_all(&len).await?;
    out.write_all(message).await?;
    out.flush().await?;

    Ok(())
}

async fn read_pascal<R: AsyncRead + Unpin>(mut input: R) -> anyhow::Result<Vec<u8>> {
    let mut len = [0; 4];
    input.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len);
    if len > 500_000 {
        anyhow::bail!("pascal message that is too big")
    }
    let mut buffer = vec![0; len as usize];
    input.read_exact(&mut buffer).await?;

    Ok(buffer)
}
