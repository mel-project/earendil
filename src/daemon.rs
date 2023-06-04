mod connection;
mod n2n;

use std::path::Path;

use earendil_topology::IdentitySecret;

use crate::config::ConfigFile;

fn read_identity(path: &Path) -> anyhow::Result<IdentitySecret> {
    Ok(stdcode::deserialize(&hex::decode(std::fs::read(path)?)?)?)
}

fn write_identity(path: &Path, identity: &IdentitySecret) -> anyhow::Result<()> {
    let encoded_identity = hex::encode(stdcode::serialize(&identity)?);
    std::fs::write(path, encoded_identity)?;
    Ok(())
}

pub fn main_daemon(config: ConfigFile) -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("earendil=debug"))
        .init();
    let identity = loop {
        match read_identity(&config.identity) {
            Ok(id) => break id,
            Err(err) => {
                log::warn!(
                    "(re)writing identity file at {:?} due to error reading: {:?}",
                    config.identity,
                    err
                );
                let new_id = IdentitySecret::generate();
                write_identity(&config.identity, &new_id)?;
            }
        }
    };
    log::info!(
        "daemon starting with fingerprint {}",
        identity.public().fingerprint()
    );
    todo!()
}
