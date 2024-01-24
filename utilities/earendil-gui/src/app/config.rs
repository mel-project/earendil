use std::path::PathBuf;

use earendil::config::ConfigFile;
use earendil_crypt::Fingerprint;
use serde::{Deserialize, Serialize};
use tap::Tap;

#[derive(Default)]
pub struct ConfigState {
    pub raw_yaml: String,
    pub gui_prefs: Prefs,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]

pub struct Prefs {
    pub daemon_mode: DaemonMode,
    pub chatting_with: Option<Fingerprint>,
}

impl Default for Prefs {
    fn default() -> Self {
        Self {
            daemon_mode: DaemonMode::Embedded,
            chatting_with: None,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DaemonMode {
    Embedded,
    Remote,
}

pub fn earendil_config_dir() -> PathBuf {
    let config_dir = dirs::config_dir().unwrap().tap_mut(|path| {
        path.push("earendil");
    });
    let _ = std::fs::create_dir_all(&config_dir);
    config_dir
}

impl ConfigState {
    /// Construct by reading from the standard location.
    pub fn load() -> anyhow::Result<Self> {
        let contents =
            std::fs::read(earendil_config_dir().tap_mut(|dir| dir.push("earendil-config.yaml")))?;
        let prefs = std::fs::read(earendil_config_dir().tap_mut(|dir| dir.push("gui-prefs.json")))?;
        let raw_yaml = String::from_utf8_lossy(&contents).into_owned();
        Ok(Self {
            raw_yaml,
            gui_prefs: serde_json::from_slice(&prefs)?,
        })
    }

    /// Persist into the usual location.
    pub fn save(&self) -> anyhow::Result<()> {
        std::fs::write(
            earendil_config_dir().tap_mut(|dir| dir.push("earendil-config.yaml")),
            self.raw_yaml.as_bytes(),
        )?;
        std::fs::write(
            earendil_config_dir().tap_mut(|dir| dir.push("gui-prefs.json")),
            serde_json::to_vec_pretty(&self.gui_prefs)?,
        )?;
        Ok(())
    }

    /// Realize as an actual daemon configuration.
    pub fn realize(&self) -> anyhow::Result<ConfigFile> {
        let cfg: ConfigFile = serde_yaml::from_str(&self.raw_yaml)?;
        Ok(cfg)
    }
}
