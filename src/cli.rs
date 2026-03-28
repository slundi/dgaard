#[derive(Serialize, Deserialize, Debug)]
pub enum ControlMessage {
    // Outgoing (Proxy -> CLI)
    Stat(StatEvent),
    Mapping { hash: u64, domain: String },

    // Incoming (CLI -> Proxy)
    AddWhitelist { domain: String },
    RemoveWhitelist { domain: String },
    AddBlacklist { domain: String },
    ReloadConfig, // Tells the proxy to re-read the TOML and all files
}
