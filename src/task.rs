pub async fn spawn_update_task(config: Arc<Config>, state: Arc<ProxyState>) {
    let interval = Duration::from_secs(config.sources.update_interval_hours * 3600);

    tokio::spawn(async move {
        loop {
            // 1. Wait for the next update cycle
            tokio::time::sleep(interval).await;

            println!("Starting scheduled rule update...");

            // 2. Download and Parse (in a blocking thread to not lag the DNS)
            match download_and_parse_rules(&config).await {
                Ok(new_lists) => {
                    // 3. Atomic Swap: The proxy now uses the new rules instantly
                    state.blocklist.store(Arc::new(new_lists.blocklist));
                    state.whitelist.store(Arc::new(new_lists.whitelist));
                    state.abp.store(Arc::new(new_lists.abp));

                    println!("Rules updated successfully.");
                }
                Err(e) => {
                    eprintln!("Update failed: {}. Retrying in 30m.", e);
                    tokio::time::sleep(Duration::from_secs(1800)).await;
                }
            }
        }
    });
}
