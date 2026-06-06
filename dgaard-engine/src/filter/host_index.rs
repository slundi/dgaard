//! Host index writer.
//!
//! Generates a compact binary file that maps every xxh3_64 hash to its source
//! domain string.  External tools (dashboard, TUI, scripts) can use this index
//! to resolve a hash back to a human-readable domain without keeping the full
//! blocklist in memory.
//!
//! ## Binary Format (little-endian)
//!
//! ```text
//! Header (9 bytes):
//!   [4] Magic   : b"DGHI"
//!   [1] Version : 0x01
//!   [4] Count   : u32 — number of records
//!
//! Records (sorted by hash for binary-search by consumers):
//!   [8] Hash    : u64
//!   [2] Len     : u16 — byte length of the domain string
//!   [*] Domain  : UTF-8 bytes (Len bytes)
//! ```

use std::{
    collections::HashMap,
    fs::File,
    io::{BufWriter, Write},
    path::Path,
};

const MAGIC: &[u8; 4] = b"DGHI";
const VERSION: u8 = 1;

/// Write the host index to `path`.
///
/// Records are sorted by hash to allow binary-search lookups by consumers.
/// The parent directory is created if it does not exist.
///
/// Returns immediately (no-op) when `path` is empty.
pub fn write_host_index(path: &str, index: &HashMap<u64, String>) -> std::io::Result<()> {
    if path.is_empty() {
        return Ok(());
    }

    if let Some(parent) = Path::new(path).parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }

    let file = File::create(path)?;
    let mut w = BufWriter::new(file);

    // Header
    w.write_all(MAGIC)?;
    w.write_all(&[VERSION])?;
    w.write_all(&(index.len() as u32).to_le_bytes())?;

    // Collect and sort by hash for deterministic, binary-searchable output
    let mut entries: Vec<(u64, &str)> = index.iter().map(|(&h, s)| (h, s.as_str())).collect();
    entries.sort_unstable_by_key(|&(h, _)| h);

    for (hash, domain) in &entries {
        let len = domain.len().min(u16::MAX as usize) as u16;
        w.write_all(&hash.to_le_bytes())?;
        w.write_all(&len.to_le_bytes())?;
        w.write_all(&domain.as_bytes()[..len as usize])?;
    }

    w.flush()?;
    println!("Host index written to {} ({} entries)", path, index.len());
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufReader, Read};

    fn read_index(path: &str) -> Vec<(u64, String)> {
        let file = File::open(path).unwrap();
        let mut r = BufReader::new(file);

        let mut magic = [0u8; 4];
        r.read_exact(&mut magic).unwrap();
        assert_eq!(&magic, MAGIC, "bad magic");

        let mut ver = [0u8; 1];
        r.read_exact(&mut ver).unwrap();
        assert_eq!(ver[0], VERSION, "bad version");

        let mut cnt = [0u8; 4];
        r.read_exact(&mut cnt).unwrap();
        let count = u32::from_le_bytes(cnt) as usize;

        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            let mut hb = [0u8; 8];
            r.read_exact(&mut hb).unwrap();

            let mut lb = [0u8; 2];
            r.read_exact(&mut lb).unwrap();
            let len = u16::from_le_bytes(lb) as usize;

            let mut db = vec![0u8; len];
            r.read_exact(&mut db).unwrap();

            out.push((u64::from_le_bytes(hb), String::from_utf8(db).unwrap()));
        }
        out
    }

    fn temp_path(suffix: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("dgaard_idx_{}_{}.bin", suffix, std::process::id()))
    }

    #[test]
    fn write_and_read_roundtrip() {
        let path = temp_path("roundtrip");
        let path_str = path.to_str().unwrap();

        let mut index = HashMap::new();
        index.insert(0xDEAD_BEEF_CAFE_BABE_u64, String::from("example.com"));
        index.insert(0x1234_5678_90AB_CDEF_u64, String::from("ads.tracker.io"));

        write_host_index(path_str, &index).unwrap();

        let entries = read_index(path_str);
        assert_eq!(entries.len(), 2);

        // Records are sorted by hash
        let hashes: Vec<u64> = entries.iter().map(|(h, _)| *h).collect();
        let mut sorted = hashes.clone();
        sorted.sort_unstable();
        assert_eq!(hashes, sorted, "records must be sorted by hash");

        let map: HashMap<u64, String> = entries.into_iter().collect();
        assert_eq!(map[&0xDEAD_BEEF_CAFE_BABE_u64], "example.com");
        assert_eq!(map[&0x1234_5678_90AB_CDEF_u64], "ads.tracker.io");

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn empty_index_writes_valid_header() {
        let path = temp_path("empty");
        let path_str = path.to_str().unwrap();

        write_host_index(path_str, &HashMap::new()).unwrap();

        let entries = read_index(path_str);
        assert!(entries.is_empty());

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn empty_path_is_noop() {
        assert!(write_host_index("", &HashMap::new()).is_ok());
    }

    #[test]
    fn creates_parent_directories() {
        let dir = std::env::temp_dir()
            .join(format!("dgaard_idx_dir_{}", std::process::id()))
            .join("subdir");
        let path = dir.join("host_mapping.bin");
        let path_str = path.to_str().unwrap();

        let mut index = HashMap::new();
        index.insert(1u64, String::from("test.com"));

        write_host_index(path_str, &index).unwrap();
        assert!(path.exists());

        std::fs::remove_dir_all(dir.parent().unwrap()).ok();
    }
}
