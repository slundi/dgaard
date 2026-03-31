use dgaard::config::Config;

mod cli;
mod config;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opts = cli::parse();

    let config_path = config::discover_path(opts.config.as_deref()).ok_or("Configuration file not found. Please provide one via --config or place it in /etc/dgaard/config.toml")?;

    let config = config::Config::load(&config_path)?;
    println!("Dgaard starting on {}", cfg.server.listen_addr);

    Ok(())
}
