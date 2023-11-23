use anyhow::Context;
use earendil::{
    config::ConfigFile,
    daemon::Daemon,
    socket::Socket,
    stream::{listener::StreamListener, Stream},
};
use futures_util::io::AsyncWriteExt;

fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("earendil=trace"))
        .init();
    let _ = smolscale::block_on(async {
        let client_daemon = spawn_daemon("./config/alice.yaml")?;
        let client_id = client_daemon.identity();
        let client_socket = Socket::bind_n2r(client_daemon, client_id, None);

        let server_daemon = spawn_daemon("./config/bob.yaml")?;
        let server_id = server_daemon.identity();
        let server_socket = Socket::bind_n2r(server_daemon, server_id, None);
        let server_ep = server_socket.local_endpoint();
        log::info!("server endpoint: {server_ep}");

        smolscale::spawn(async move {
            let mut stream_listener = StreamListener::listen(server_socket);
            log::trace!("LISTENING!!");

            loop {
                match stream_listener.accept().await {
                    Ok(server_stream) => {
                        log::debug!("GOT a STREAM~~~~~~~~~~~~~~~~~~~~");
                    }
                    Err(e) => log::warn!("server stream accept error! {e}"),
                }
            }
        })
        .detach();

        let mut client_stream = Stream::connect(client_socket, server_ep).await?;
        log::trace!("CLIENT: established stream!");

        let data = b"hello from stream";
        let _sz = client_stream.write(data).await?;

        anyhow::Ok(())
    });

    loop {
        std::thread::park();
    }
}

fn spawn_daemon(path: &str) -> anyhow::Result<Daemon> {
    let config: ConfigFile =
        serde_yaml::from_slice(&std::fs::read(path).context("cannot read config file")?)
            .context("syntax error in config file")?;
    let daemon = Daemon::init(config)?;
    Ok(daemon)
}
