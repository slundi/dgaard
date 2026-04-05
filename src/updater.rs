use std::time::Duration;

use crate::{CONFIG, filter::reload_lists};

pub async fn spawn_update_task() {
    let hours = CONFIG.load().sources.update_interval_hours;
    let interval = Duration::from_hours(hours.into());

    tokio::spawn(async move {
        loop {
            // 1. Wait for the next update cycle
            tokio::time::sleep(interval).await;

            println!("Starting scheduled rule update...");

            // 2. Download and Parse (in a blocking thread to not lag the DNS)
            reload_lists();
        }
    });
}
