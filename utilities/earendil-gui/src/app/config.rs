use std::path::PathBuf;

use earendil::config::ConfigFile;
use tap::Tap;

#[derive(Default)]
pub struct ConfigState {
    pub raw_yaml: String,
}

fn yaml_dir() -> PathBuf {
    let config_dir = dirs::config_dir().unwrap().tap_mut(|path| {
        path.push("earendil");
    });
    let _ = std::fs::create_dir_all(&config_dir);
    config_dir
        .clone()
        .tap_mut(|d| d.push("earendil-config.yaml"))
}

impl ConfigState {
    /// Construct by reading from the standard location.
    pub fn load() -> anyhow::Result<Self> {
        let contents = std::fs::read(&yaml_dir())?;

        let raw_yaml = String::from_utf8_lossy(&contents).into_owned();
        Ok(Self { raw_yaml })
    }

    /// Persist into the usual location.
    pub fn save(&self) -> anyhow::Result<()> {
        std::fs::write(yaml_dir(), self.raw_yaml.as_bytes())?;
        Ok(())
    }

    /// Realize as an actual daemon configuration.
    pub fn realize(&self) -> anyhow::Result<ConfigFile> {
        let cfg: ConfigFile = serde_yaml::from_str(&self.raw_yaml)?;
        Ok(cfg)
    }
}
