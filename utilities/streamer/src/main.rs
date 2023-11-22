use anyhow::Context;
use earendil::{
    config::ConfigFile,
    daemon::Daemon,
    socket::Socket,
    stream::{listener::StreamListener, Stream},
};
use futures_util::{io::AsyncWriteExt, AsyncReadExt};

fn main() -> anyhow::Result<()> {
    let _ = smolscale::block_on(async {
        let client_daemon = spawn_daemon("config/alice.yaml")?;
        let server_daemon = spawn_daemon("config/bob.yaml")?;

        let client_id = client_daemon.identity();
        let server_id = server_daemon.identity();

        let client_socket = Socket::bind_n2r(client_daemon, client_id, None);
        let server_socket = Socket::bind_n2r(server_daemon, server_id, None);

        let server_ep = server_socket.local_endpoint();
        println!("server endpoint: {server_ep}");

        smolscale::spawn(async move {
            let mut stream_listener = StreamListener::listen(server_socket);
            println!("listening");

            let mut server_stream = stream_listener.accept().await.unwrap();
            println!("got streams");

            let mut array = [0; 1000];
            let buf = &mut array[..];
            let sz = server_stream.read(buf).await.unwrap();
            println!("finished reading");

            println!("{:?}", &buf[..sz]);
        })
        .detach();

        let mut client_stream = Stream::connect(client_socket, server_ep).await?;
        println!("connected to stream");

        let data = b"hello strem";
        let _sz = client_stream.write(data).await?;
        println!("finished writing");

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
