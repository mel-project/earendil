use std::path::Path;

use earendil_crypt::IdentitySecret;

pub fn read_identity(path: &Path) -> anyhow::Result<IdentitySecret> {
    Ok(stdcode::deserialize(&hex::decode(std::fs::read(path)?)?)?)
}

pub fn write_identity(path: &Path, identity: &IdentitySecret) -> anyhow::Result<()> {
    let encoded_identity = hex::encode(stdcode::serialize(&identity)?);
    std::fs::write(path, encoded_identity)?;
    Ok(())
}

pub fn get_or_create_id(path: &Path) -> anyhow::Result<IdentitySecret> {
    loop {
        match read_identity(path) {
            Ok(id) => break Ok(id),
            Err(err) => {
                log::warn!(
                    "(re)writing identity file at {:?} due to error reading: {:?}",
                    path,
                    err
                );
                let new_id = IdentitySecret::generate();
                write_identity(path, &new_id)?;
            }
        }
    }
}
