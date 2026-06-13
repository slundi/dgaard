mod config;
mod fetch;
mod model;
mod output;
mod stats;

use std::path::Path;

/// Compute blocklist statistics and write JSON + CSV output.
#[derive(argh::FromArgs)]
struct Args {
    /// output directory (default: ./output)
    #[argh(option, short = 'o', default = "String::from(\"output\")")]
    output_dir: String,

    /// number of top TLDs and words to keep per list (default: 20)
    #[argh(option, short = 'n', default = "20usize")]
    top: usize,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let args: Args = argh::from_env();
    std::fs::create_dir_all(&args.output_dir)?;

    let client = fetch::build_client();
    let mut all_data: Vec<model::ListData> = Vec::new();

    for source in config::SOURCES {
        log::info!("Fetching {} ({}) ...", source.name, source.url);
        match fetch::fetch(&client, source.url).await {
            Ok(content) => {
                let data =
                    stats::parse_list_data(source.name, source.url, source.category, &content);
                log::info!(
                    "  {} entries ({} plain, {} wildcard, {} regex)",
                    data.domains.len() + data.wildcard_count + data.regex_count,
                    data.domains.len(),
                    data.wildcard_count,
                    data.regex_count,
                );
                all_data.push(data);
            }
            Err(e) => {
                log::warn!("Failed to fetch {}: {e}", source.name);
            }
        }
    }

    let global = stats::compute_global_stats(&all_data, args.top);
    let list_stats: Vec<_> = all_data
        .iter()
        .map(|d| stats::compute_list_stats(d, args.top))
        .collect();
    let categories = stats::compute_categories(&all_data);
    let overlap = stats::compute_overlap_matrix(&all_data);

    let generated_at = {
        use std::time::{SystemTime, UNIX_EPOCH};
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let (y, mo, d, h, mi, s) = epoch_to_datetime(secs);
        format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
    };

    let report = model::Report {
        generated_at,
        global,
        lists: list_stats,
        categories,
        overlap_matrix: overlap,
    };

    let out = Path::new(&args.output_dir);
    output::write_json(&report, &out.join("stats.json"))?;
    output::write_csv(&all_data, &out.join("stats.csv"))?;

    println!(
        "Done. {} lists processed, {} unique domains. Output: {}",
        all_data.len(),
        report.global.unique_entries,
        args.output_dir,
    );

    Ok(())
}

/// Convert a Unix timestamp (seconds) to (year, month, day, hour, minute, second).
fn epoch_to_datetime(secs: u64) -> (u32, u32, u32, u32, u32, u32) {
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400;

    // Gregorian calendar calculation
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };

    (y as u32, mo as u32, d as u32, h as u32, m as u32, s as u32)
}
