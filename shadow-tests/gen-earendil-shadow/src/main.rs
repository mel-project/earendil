use anyhow::Context;
use bip39::Mnemonic;
use clap::Parser;
use earendil_crypt::{Fingerprint, IdentitySecret};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sosistab2_obfsudp::ObfsUdpSecret;

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
};

/// YAML-serializable adjacencies representation
#[derive(Serialize, Deserialize)]
struct Adjacencies {
    adjacencies: Vec<(String, String)>,
}

#[derive(Parser)]
struct Args {
    config: PathBuf,
    name: String,
    #[arg(short, long)]
    shadow: bool,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let yaml_path = args.config;
    let shadow = args.shadow;

    let adjacencies: Adjacencies =
        serde_yaml::from_slice(&std::fs::read(yaml_path).context("cannot read config file")?)?;
    let adjacencies = get_adjacencies(&adjacencies)?;

    let mut ips: HashMap<String, Ipv4Addr> = HashMap::new();
    let mut obfsudp_ports: HashMap<String, u16> = HashMap::new();
    let mut secrets: HashMap<String, String> = HashMap::new();
    let mut identity_seeds: HashMap<String, String> = HashMap::new();
    let mut fingerprints: HashMap<String, Fingerprint> = HashMap::new();
    let mut cookies: HashMap<String, [u8; 32]> = HashMap::new();
    let mut control_ports: HashMap<String, u16> = HashMap::new();

    let min: u32 = Ipv4Addr::new(200, 64, 1, 1).into();
    let max: u32 = Ipv4Addr::new(200, 64, 255, 255).into();
    let mut listen_port = 12000;

    for (i, node_name) in adjacencies.keys().enumerate() {
        // ip
        let i = i as u32;
        if min + i < max {
            let ip = if shadow {
                (min + i).into()
            } else {
                Ipv4Addr::new(127, 0, 0, 1)
            };
            ips.insert(node_name.to_owned(), ip);
        } else {
            anyhow::bail!("too many nodes")
        }

        // port
        obfsudp_ports.insert(node_name.to_owned(), listen_port);
        listen_port += 1;

        // control listen
        control_ports.insert(node_name.to_owned(), listen_port);
        listen_port += 1;

        // secret
        let secret = generate_seed()?;
        secrets.insert(node_name.to_owned(), secret.clone());

        // identity seed
        let identity_seed = generate_seed()?;
        identity_seeds.insert(node_name.to_owned(), identity_seed.clone());

        // identity
        let identity = IdentitySecret::from_bytes(&earendil_crypt::kdf_from_human(
            &identity_seed,
            "identity_kdf_salt",
        ));

        // fingerprint
        let fingerprint = identity.public().fingerprint();
        fingerprints.insert(node_name.to_owned(), fingerprint);

        // cookies
        let obfs_udp_secret =
            ObfsUdpSecret::from_bytes(*blake3::hash(secret.as_bytes()).as_bytes());
        let cookie = *obfs_udp_secret.to_public().as_bytes();
        cookies.insert(node_name.to_owned(), cookie);
    }
    // construct strings
    let mut earendil_configs: Vec<(String, String)> = Vec::new();
    let mut shadow_hosts: HashMap<String, serde_json::Value> = HashMap::new();
    for (node_name, neighbors) in adjacencies.iter() {
        // earendil config
        let out_routes: HashMap<String, serde_json::Value> = neighbors
            .iter()
            .map(|neigh| {
                let ip = if shadow {
                    IpAddr::V4(ips.get(neigh).unwrap().to_owned())
                } else {
                    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
                };
                (
                    neigh.to_owned(),
                    json!({
                            "fingerprint": fingerprints.get(neigh).unwrap().to_string(),
                            "protocol": "obfsudp",
                            "connect": SocketAddr::new(ip, *obfsudp_ports.get(neigh).unwrap()).to_string(),
                            "cookie": hex::encode(cookies.get(neigh).unwrap()),

                    }),
                )
            })
            .collect();
        let earendil_json = if shadow {
            json!({
                "identity_seed": identity_seeds.get(node_name).unwrap(),
                "in_routes":
                {
                    "main_udp":
                    {
                        "protocol": "obfsudp",
                        "listen": "0.0.0.0:".to_owned() + &obfsudp_ports.get(node_name).unwrap().to_string(),
                        "secret": secrets.get(node_name).unwrap()
                    }
                },
                "out_routes": out_routes
            })
        } else {
            json!({
                "identity_seed": identity_seeds.get(node_name).unwrap(),
                "control_listen": "127.0.0.1:".to_owned() + &control_ports.get(node_name).unwrap().to_string(),
                "in_routes":
                {
                    "main_udp":
                    {
                        "protocol": "obfsudp",
                        "listen": "0.0.0.0:".to_owned() + &obfsudp_ports.get(node_name).unwrap().to_string(),
                        "secret": secrets.get(node_name).unwrap()
                    }
                },
                "out_routes": out_routes
            })
        };
        let fingerprint_comment = format!(
            "# {} fingerprint: {}\n",
            node_name,
            fingerprints.get(node_name).unwrap().to_string()
        );
        earendil_configs.push((
            node_name.to_owned(),
            fingerprint_comment + &serde_yaml::to_string(&earendil_json)?,
        ));

        // shadow host
        let shadow_json = json!({
            "ip_addr": ips.get(node_name).unwrap().to_string(),
            "network_node_id": 0,
            "processes": [
                {
                    "path": "earendil",
                    "args": format!("daemon --config {}-cfg.yaml", node_name),
                    "expected_final_state": "running",
                }
            ]
        });
        shadow_hosts.insert(node_name.to_owned(), shadow_json);
    }

    let dir_path = &("../".to_owned() + &args.name);
    if shadow {
        let shadow_yaml = serde_yaml::to_string(&json!({
            "general": {
                "model_unblocked_syscall_latency": true,
                "template_directory": "./configs/",
                "stop_time": "300s"
            },
            "network": {
                "graph": {
                    "type": "1_gbit_switch"
                }
            },
            "hosts": shadow_hosts
        }))?;
        // write everything to files, building a nice directory tree
        std::fs::create_dir_all(format!("{dir_path}/configs/hosts/"))?;
        std::fs::write(format!("{dir_path}/shadow.yaml"), shadow_yaml)?;
        for (name, earendil_cfg) in earendil_configs {
            std::fs::create_dir(format!("{dir_path}/configs/hosts/{name}"))?;
            std::fs::write(
                format!("{dir_path}/configs/hosts/{name}/{name}-cfg.yaml"),
                earendil_cfg,
            )?;
        }
    } else {
        std::fs::create_dir_all(dir_path)?;
        for (name, earendil_cfg) in earendil_configs {
            std::fs::write(format!("{dir_path}/{name}-cfg.yaml"), earendil_cfg)?;
        }
    }

    Ok(())
}

fn get_adjacencies(adjacencies: &Adjacencies) -> anyhow::Result<HashMap<String, HashSet<String>>> {
    let mut map: HashMap<String, HashSet<String>> = HashMap::new();
    for (n1, n2) in adjacencies.adjacencies.iter() {
        map.entry(n1.to_owned()).or_default().insert(n2.to_owned());
        map.entry(n2.to_owned()).or_default();
    }
    Ok(map)
}

fn generate_seed() -> anyhow::Result<String> {
    let entropy: [u8; 16] = rand::random();
    let mnemonic = Mnemonic::from_entropy(&entropy)?;
    Ok(mnemonic.to_string().replace(" ", "-"))
}
