mod cli;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opts = cli::parse();

    // TODO: load config from opts.config path (or default)
    let _ = opts.config;

    Ok(())
}
