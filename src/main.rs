mod cli;
mod config;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opts = cli::parse();

    let config_path = config::discover_path(opts.config.as_deref());
    // TODO: parse config file at config_path
    let _ = config_path;

    Ok(())
}
