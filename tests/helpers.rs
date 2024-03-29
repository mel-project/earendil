use std::{
    collections::HashSet,
    env, fs,
    io::{self, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    ops::RangeInclusive,
    path::Path,
    time::Duration,
};

use earendil::{
    config::{ConfigFile, Identity, InRouteConfig, LinkPrice, OutRouteConfig},
    daemon::Daemon,
};
use rand::{rngs::StdRng, Rng, SeedableRng};
use smol::Timer;
use sosistab2_obfsudp::ObfsUdpSecret;
use std::net::TcpStream;
use tracing_subscriber::{util::SubscriberInitExt};

type InRoutes = Vec<(String, InRouteConfig)>;
type OutRoutes = Vec<(String, OutRouteConfig)>;

// initializes env vars
pub fn env_vars() {
    env::set_var("SOSISTAB2_NO_SLEEP", "1");
}

// sleeps while displaying progress
pub async fn sleep(secs: u64) {
    println!("sleeping for {secs} seconds...");
    for i in 0..=secs {
        let percentage = i as f64 / secs as f64 * 100.0;
        let progress = (percentage as usize) / 2; // For a progress bar of 50 characters
        let remaining = 50 - progress;
        print!(
            "\r[{}>{}]{:.2}% ",
            "=".repeat(progress),
            " ".repeat(remaining),
            percentage
        );
        io::stdout().flush().unwrap();
        Timer::after(Duration::from_secs(1)).await;
    }
    println!();
}

// generates a barebones config
pub fn gen_cfg(
    identity: Identity,
    control_listen: SocketAddr,
    in_routes: InRoutes,
    out_routes: OutRoutes,
) -> ConfigFile {
    let db_path = None;
    let in_routes = in_routes.into_iter().collect();
    let out_routes = out_routes.into_iter().collect();
    let udp_forwards = vec![];
    let tcp_forwards = vec![];
    let socks5 = None;
    let havens = vec![];

    ConfigFile {
        identity: Some(identity),
        db_path,
        control_listen,
        in_routes,
        out_routes,
        udp_forwards,
        tcp_forwards,
        socks5,
        havens,
        auto_settle: None,
    }
}

// finds a random, unused socket address on localhost
fn free_port(rng: &mut StdRng) -> u16 {
    loop {
        let port: u16 = rng.gen_range(1024..=65535);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);

        match TcpStream::connect(addr) {
            Ok(_) => {
                eprintln!("port {} is bound", port);
                continue;
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                eprintln!("port {} is free", port);
                return port;
            }
            Err(e) => {
                eprintln!("other error with port {port}: {e}");
                continue;
            }
        }
    }
}

// creates random in/out routes for a ConfigFile, given a vector of existing relays
fn routes(
    rng: &mut StdRng,
    existing_relays: &Vec<ConfigFile>,
    is_relay: bool,
    num_outroutes_range: RangeInclusive<u8>,
) -> anyhow::Result<(InRoutes, OutRoutes)> {
    let secret = "secret".to_string();
    let link_price = LinkPrice {
        max_outgoing_price: 1,
        incoming_price: 0,
        incoming_debt_limit: 100,
    };
    let mut in_routes = vec![];

    if is_relay {
        in_routes.push((
            "obfsudp".to_string(),
            InRouteConfig::Obfsudp {
                listen: format!("0.0.0.0:{}", free_port(rng)).parse()?,
                secret,
                link_price,
            },
        ))
    }

    let num_outroutes = rng.gen_range(num_outroutes_range);
    let mut out_routes: Vec<(String, OutRouteConfig)> = vec![];
    let mut seen = HashSet::new();

    for _ in 0..num_outroutes {
        let mut relay_cfg;
        loop {
            let relay_index = rng.gen_range(0..existing_relays.len());
            relay_cfg = existing_relays.get(relay_index).unwrap();

            let relay_fp = relay_cfg
                .identity
                .clone()
                .unwrap()
                .actualize()?
                .public()
                .fingerprint();

            if seen.contains(&relay_fp) {
                continue;
            } else {
                seen.insert(relay_fp);
                break;
            }
        }
        let (connect, cookie, link_price) = match relay_cfg.in_routes.get("obfsudp").unwrap() {
            InRouteConfig::Obfsudp {
                mut listen,
                secret,
                link_price,
            } => {
                listen.set_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
                (
                    listen,
                    *ObfsUdpSecret::from_bytes(*blake3::hash(secret.as_bytes()).as_bytes())
                        .to_public()
                        .as_bytes(),
                    *link_price,
                )
            }
        };
        let relay_id = match &relay_cfg.identity {
            Some(Identity::IdentitySeed(seed)) => seed.clone(),
            _ => panic!("no id seed"),
        };

        out_routes.push((
            relay_id,
            OutRouteConfig::Obfsudp {
                fingerprint: relay_cfg
                    .identity
                    .clone()
                    .unwrap()
                    .actualize()?
                    .public()
                    .fingerprint(),
                connect,
                cookie,
                link_price,
            },
        ));
    }
    Ok((in_routes, out_routes.into_iter().collect()))
}

pub fn gen_seed(phrase: &str) -> [u8; 32] {
    *blake3::hash(phrase.as_bytes()).as_bytes()
}

// creates arbitrarily-sized vectors of randomly (but deterministically) interconnected relay and client daemon configs
pub fn gen_network(
    num_relays: u8,
    num_clients: u16,
    seed: Option<[u8; 32]>,
) -> anyhow::Result<(Vec<ConfigFile>, Vec<ConfigFile>)> {
    let seed = if let Some(s) = seed { s } else { [1; 32] };
    let mut rng: StdRng = SeedableRng::from_seed(seed);
    let mut relay_configs = vec![];

    for i in 0..num_relays {
        let relay_id = Identity::IdentitySeed(format!("relay{i}"));
        let control_listen = format!("127.0.0.1:{}", free_port(&mut rng)).parse()?;
        // range start is 0 for i = 0 and 1 otherwise; end grows slowly according to √i
        let num_outroutes_range = (i > 0) as u8..=(i > 0) as u8 * (i as f64).sqrt() as u8;
        let (in_routes, out_routes) = routes(&mut rng, &relay_configs, true, num_outroutes_range)?;
        let relay_cfg = gen_cfg(
            relay_id,
            control_listen,
            in_routes,
            out_routes.into_iter().collect(),
        );

        relay_configs.push(relay_cfg);
    }

    let mut client_configs = vec![];

    for i in 0..num_clients {
        let client_id = Identity::IdentitySeed(format!("client{i}"));
        let control_listen = format!("127.0.0.1:{}", free_port(&mut rng)).parse()?;
        let num_outroutes_range = 1..=(num_relays as f64).sqrt() as u8;
        let (in_routes, out_routes) = routes(&mut rng, &relay_configs, false, num_outroutes_range)?;
        let client_cfg = gen_cfg(client_id, control_listen, in_routes, out_routes);

        client_configs.push(client_cfg);
    }

    Ok((relay_configs, client_configs))
}

pub fn configs_to_daemons(configs: Vec<ConfigFile>) -> anyhow::Result<Vec<Daemon>> {
    configs.into_iter().map(Daemon::init).collect()
}

pub fn spawn_network(
    num_relays: u8,
    num_clients: u16,
    seed: Option<[u8; 32]>,
) -> anyhow::Result<(Vec<Daemon>, Vec<Daemon>)> {
    let (relay_configs, client_configs) = gen_network(num_relays, num_clients, seed)?;
    let relays: Vec<Daemon> = relay_configs
        .into_iter()
        .map(Daemon::init)
        .collect::<anyhow::Result<Vec<Daemon>>>()?;
    let clients: Vec<Daemon> = client_configs
        .into_iter()
        .map(Daemon::init)
        .collect::<anyhow::Result<Vec<Daemon>>>()?;

    Ok((relays, clients))
}

// writes a ConfigFile to the given path, creating the parent dir if it doesn't exist
pub fn config_to_yaml_file(config: &ConfigFile, file_path: &str) -> std::io::Result<()> {
    let yaml_string = serde_yaml::to_string(&config).expect("Failed to serialize config to YAML");

    let parent_dir = Path::new(file_path).parent().unwrap();
    fs::create_dir_all(parent_dir)?;

    let mut file = fs::File::create(file_path)?;
    let id = match &config.identity {
        Some(id) => id.actualize().unwrap(),
        None => panic!("id generated in unexpected format"),
    };
    file.write_all(format!("# fingerprint: {}\n", id.public().fingerprint()).as_bytes())?;
    file.write_all(yaml_string.as_bytes())?;

    Ok(())
}
