use std::{
    collections::HashSet,
    env, fs,
    io::Write,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    ops::RangeInclusive,
    path::Path,
};

use earendil::{
    config::{
        ConfigFile, HavenForwardConfig, Identity, InRouteConfig, LinkPrice, OutRouteConfig, Socks5,
        TcpForwardConfig, UdpForwardConfig,
    },
    daemon::Daemon,
};
use rand::{rngs::StdRng, Rng, SeedableRng};
use sosistab2_obfsudp::ObfsUdpSecret;
use std::net::TcpStream;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

type InRoutes = Vec<(String, InRouteConfig)>;
type OutRoutes = Vec<(String, OutRouteConfig)>;

// sets up a global tracing subscriber and initializes env vars
pub fn prelude() {
    let _ = tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().compact())
        .with(
            EnvFilter::builder()
                .with_default_directive("earendil=debug".parse().unwrap())
                .from_env_lossy(),
        )
        .try_init();

    env::set_var("SOSISTAB2_NO_SLEEP", "1");
}

// generates a barebones config
fn gen_cfg(
    identity: Identity,
    control_listen: SocketAddr,
    in_routes: Vec<(String, InRouteConfig)>,
    out_routes: Vec<(String, OutRouteConfig)>,
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
    }
}

// finds a random, unused socket address on localhost
fn free_address(rng: &mut StdRng) -> SocketAddr {
    loop {
        let port: u16 = rng.gen_range(1024..=65535);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);

        match TcpStream::connect(addr) {
            Ok(_) => {
                println!("port {port} is bound");
                continue;
            }
            Err(_) => {
                println!("port {port} is free");
                return addr;
            }
        }
    }
}

// creates random in/out routes
fn routes(
    rng: &mut StdRng,
    relay_configs: &Vec<ConfigFile>,
    is_relay: bool,
    outroute_range: RangeInclusive<u8>,
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
                listen: free_address(rng),
                secret,
                link_price,
            },
        ))
    }

    let num_out_routes = rng.gen_range(outroute_range);
    let mut out_routes: Vec<(String, OutRouteConfig)> = vec![];
    let mut seen = HashSet::new();

    for _ in 0..num_out_routes {
        let mut relay_cfg;
        loop {
            let relay_index = rng.gen_range(0..relay_configs.len());
            relay_cfg = relay_configs.get(relay_index).unwrap();
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
                listen,
                secret,
                link_price,
            } => (
                *listen,
                *ObfsUdpSecret::from_bytes(*blake3::hash(secret.as_bytes()).as_bytes())
                    .to_public()
                    .as_bytes(),
                *link_price,
            ),
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

// creates arbitrarily-sized vectors of randomly (but deterministically) interconnected relay and client daemons
pub fn spawn_network(
    num_relays: u8,
    num_clients: u16,
    seed: Option<[u8; 32]>,
) -> anyhow::Result<(Vec<Daemon>, Vec<Daemon>)> {
    let seed = if let Some(s) = seed { s } else { [1; 32] };
    let mut rng: StdRng = SeedableRng::from_seed(seed);
    let mut relay_configs = vec![];

    for i in 0..num_relays {
        println!("relay i = {i}");
        let relay_id = Identity::IdentitySeed(format!("relay{i}"));
        let control_listen = free_address(&mut rng);
        let outroute_range = 0..=(i as f64).sqrt() as u8;
        let (in_routes, out_routes) = routes(&mut rng, &relay_configs, true, outroute_range)?;
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
        println!("client i = {i}");
        let client_id = Identity::IdentitySeed(format!("client{i}"));
        let control_listen = free_address(&mut rng);
        let outroute_range = 1..=(num_relays as f64).sqrt() as u8;
        println!("outrout range: {:?}", &outroute_range);
        let (in_routes, out_routes) = routes(&mut rng, &relay_configs, false, outroute_range)?;
        let client_cfg = gen_cfg(client_id, control_listen, in_routes, out_routes);

        client_configs.push(client_cfg);
    }

    for (i, config) in [relay_configs.clone(), client_configs.clone()]
        .iter()
        .flatten()
        .enumerate()
    {
        config_to_yaml_file(config, &format!("./z/{i}"))?;
    }

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

// adds a udp forward to a config
pub fn add_udp_forward(config: ConfigFile, udp_forward: UdpForwardConfig) -> ConfigFile {
    let mut udp_forwards = config.udp_forwards;
    udp_forwards.push(udp_forward);

    ConfigFile {
        identity: config.identity,
        db_path: config.db_path,
        control_listen: config.control_listen,
        in_routes: config.in_routes,
        out_routes: config.out_routes,
        udp_forwards,
        tcp_forwards: config.tcp_forwards,
        socks5: config.socks5,
        havens: config.havens,
    }
}

// adds a tcp forward to a config
pub fn add_tcp_forward(config: ConfigFile, tcp_forward: TcpForwardConfig) -> ConfigFile {
    let mut tcp_forwards = config.tcp_forwards;
    tcp_forwards.push(tcp_forward);

    ConfigFile {
        identity: config.identity,
        db_path: config.db_path,
        control_listen: config.control_listen,
        in_routes: config.in_routes,
        out_routes: config.out_routes,
        udp_forwards: config.udp_forwards,
        tcp_forwards,
        socks5: config.socks5,
        havens: config.havens,
    }
}

// adds socks5 to a config
pub fn add_socks5(config: ConfigFile, socks5: Socks5) -> ConfigFile {
    ConfigFile {
        identity: config.identity,
        db_path: config.db_path,
        control_listen: config.control_listen,
        in_routes: config.in_routes,
        out_routes: config.out_routes,
        udp_forwards: config.udp_forwards,
        tcp_forwards: config.tcp_forwards,
        socks5: Some(socks5),
        havens: config.havens,
    }
}

// adds a haven to a config
pub fn add_haven(config: ConfigFile, haven: HavenForwardConfig) -> ConfigFile {
    let mut havens = config.havens;
    havens.push(haven);

    ConfigFile {
        identity: config.identity,
        db_path: config.db_path,
        control_listen: config.control_listen,
        in_routes: config.in_routes,
        out_routes: config.out_routes,
        udp_forwards: config.udp_forwards,
        tcp_forwards: config.tcp_forwards,
        socks5: config.socks5,
        havens,
    }
}

// writes a ConfigFile to the given path, creating the parent dir if it doesn't exist
pub fn config_to_yaml_file(config: &ConfigFile, file_path: &str) -> std::io::Result<()> {
    let yaml_string = serde_yaml::to_string(&config).expect("Failed to serialize config to YAML");

    let parent_dir = Path::new(file_path).parent().unwrap();
    fs::create_dir_all(parent_dir)?;

    let mut file = fs::File::create(file_path)?;
    file.write_all(yaml_string.as_bytes())?;
    Ok(())
}
