use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

use clap::{Parser, Subcommand};
use smol::{net::UdpSocket, stream::StreamExt, Timer};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// udp-spammer client-side
    Client {
        #[arg(long, short)]
        /// send [rate] many packets per second
        rate: u64,

        #[arg(long, short, default_value = "127.0.0.1:12223")]
        /// address of server
        server: SocketAddr,
    },

    Server {
        #[arg(long, short, default_value = "12223")]
        listen: u16,
    },
}

fn main() {
    match Args::parse().command {
        Commands::Client { rate, server } => smolscale::block_on(async move {
            match uspammer_client(rate, server).await {
                Ok(_) => eprintln!("OH NO client returned!"),
                Err(e) => eprintln!("OH NO client ERROR: {e}"),
            }
        }),
        Commands::Server { listen } => smolscale::block_on(async move {
            match uspammer_server(listen).await {
                Ok(_) => eprintln!("OH NO server returned!"),
                Err(e) => eprintln!("OH NO server ERROR: {e}"),
            }
        }),
    }
}

async fn uspammer_client(rate: u64, server: SocketAddr) -> anyhow::Result<()> {
    if rate == 0 {
        anyhow::bail!("rate must be positive")
    }

    let start_time = Instant::now();
    let skt = UdpSocket::bind("0.0.0.0:0").await?;

    let socket = skt.clone();
    let _up_task = smolscale::spawn(async move {
        let mut send_counter: u64 = 0;
        let mut timer = Timer::interval(Duration::from_secs_f64(1.0 / rate as f64));

        loop {
            match socket.send_to(&send_counter.to_ne_bytes(), server).await {
                Ok(_) => {
                    send_counter += 1;
                    timer.next().await;
                }
                Err(e) => {
                    eprintln!("ERROR sending packet: {e}");
                    continue;
                }
            };
        }
    });

    let mut recv_counter: u64 = 0;
    let mut buf = [0u8; 8];
    loop {
        skt.recv_from(&mut buf).await?;
        recv_counter += 1;
        let speed = recv_counter as f64 / start_time.elapsed().as_secs_f64().max(1.0);
        eprintln!(
            "recvd pkt {} ---------- speed is {:.2} pkts/s",
            u64::from_ne_bytes(buf),
            speed
        )
    }
}

async fn uspammer_server(listen_port: u16) -> anyhow::Result<()> {
    let socket = UdpSocket::bind(format!("0.0.0.0:{}", listen_port)).await?;
    let mut buf = [0u8; 8];

    loop {
        let (len, addr) = socket.recv_from(&mut buf).await?;
        eprintln!("SERVER: received packet {}!", u64::from_ne_bytes(buf));
        socket.send_to(&buf[..len], addr).await.unwrap();
    }
}
