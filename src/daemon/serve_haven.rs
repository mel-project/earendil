use crate::HavenHandler;
use crate::{context::DaemonContext, HavenConfig, HavenListener, PooledListener};
use anyhow::Context as _;
use futures::AsyncReadExt;
use nursery_macro::nursery;
use smol::future::FutureExt;

pub async fn serve_haven(ctx: &DaemonContext, cfg: &HavenConfig) -> anyhow::Result<()> {
    let identity = cfg.identity.actualize_haven()?;
    let listener = PooledListener::new(
        HavenListener::bind(ctx, identity, cfg.listen_port, cfg.rendezvous).await?,
    );
    nursery!({
        loop {
            let client = listener
                .accept()
                .await
                .context("could not accept another from PooledListener")?;
            let handler = &cfg.handler;
            spawn!(async move {
                match handler {
                    HavenHandler::TcpService { upstream } => {
                        tracing::debug!(upstream = debug(upstream), "serving a tcp service");
                        let upstream = smol::net::TcpStream::connect(upstream).await?;
                        let (read_client, write_client) = client.split();
                        smol::io::copy(read_client, upstream.clone())
                            .race(smol::io::copy(upstream.clone(), write_client))
                            .await?
                    }
                    HavenHandler::SimpleProxy => {
                        let connect_to = String::from_utf8_lossy(client.metadata());
                        tracing::debug!(connect_to = debug(&connect_to), "serving SimpleProxy");
                        let upstream =
                            smol::net::TcpStream::connect(connect_to.to_string()).await?;
                        let (read_client, write_client) = client.split();
                        smol::io::copy(read_client, upstream.clone())
                            .race(smol::io::copy(upstream.clone(), write_client))
                            .await?
                    }
                };
                anyhow::Ok(())
            })
            .detach()
        }
    })
}
