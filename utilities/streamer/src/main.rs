use std::time::Duration;

use anyhow::Context;

use earendil::{
    config::ConfigFile,
    daemon::Daemon,
    socket::Socket,
    stream::{HavenStream, StreamListener},
};
use earendil_crypt::RelayIdentitySecret;
use futures_util::{io::AsyncWriteExt, AsyncReadExt};
use smol::Timer;
use smolscale::reaper::TaskReaper;

fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("earendil=trace,streamer=trace"),
    )
    .init();
    smolscale::block_on(async {
        let client_daemon = spawn_daemon("./config/alice.yaml")?;
        let client_socket = Socket::bind_n2r(&client_daemon, RelayIdentitySecret::generate(), None);

        Timer::after(Duration::from_secs(1)).await;

        let server_daemon = spawn_daemon("./config/bob.yaml")?;
        let server_id = server_daemon.identity();
        let server_socket = Socket::bind_n2r(&server_daemon, server_id, None);
        let server_ep = server_socket.local_endpoint();
        log::info!("server endpoint: {server_ep}");

        Timer::after(Duration::from_secs(10)).await;

        // client_socket
        //     .send_to(b"hi server".to_vec().into(), server_ep)
        //     .await?;
        // log::debug!("sent hello!");
        // let (_, src_ep) = server_socket.recv_from().await?;
        // log::debug!("received hello!");

        smolscale::spawn(async move {
            let mut stream_listener = StreamListener::listen(server_socket);
            log::trace!("LISTENING!!");

            let server_streamtasks = TaskReaper::new();
            loop {
                match stream_listener.accept().await {
                    Ok(mut server_stream) => {
                        log::debug!("GOT a STREAM~~~~~~~~~~~~~~~~~~~~");
                        let task = smolscale::spawn(async move {
                            scopeguard::defer!(log::warn!("oh no somehow handler died"));
                            loop {
                                let mut buf = [0u8; 10000];
                                let len = server_stream.read(&mut buf).await.unwrap();
                                log::debug!(
                                    "SERVER: {}",
                                    String::from_utf8(buf[..len].to_vec()).unwrap()
                                );
                            }
                        });
                        server_streamtasks.attach(task);
                    }
                    Err(e) => log::warn!("server stream accept error! {e}"),
                }
            }
        })
        .detach();

        let mut client_stream = HavenStream::connect(client_socket, server_ep).await?;
        log::trace!("CLIENT: established stream!");

        loop {
            let data = b"hello!";
            let _sz = client_stream.write(data).await?;
            log::debug!("CLIENT: hello!");
            Timer::after(Duration::from_secs(2)).await;
        }
        // anyhow::Ok(())
    })
}

fn spawn_daemon(path: &str) -> anyhow::Result<Daemon> {
    let config: ConfigFile =
        serde_yaml::from_slice(&std::fs::read(path).context("cannot read config file")?)
            .context("syntax error in config file")?;
    let daemon = Daemon::init(config)?;
    Ok(daemon)
}
