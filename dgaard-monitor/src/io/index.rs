use std::collections::HashMap;
use std::io::{BufReader, Read};

use crate::error::MonitorError;

const MAGIC: &[u8; 4] = b"DGHI";
const VERSION: u8 = 0x01;

pub fn read_host_index(path: &str) -> Result<HashMap<u64, String>, MonitorError> {
    let file = std::fs::File::open(path)?;
    let mut reader = BufReader::new(file);

    // Read header: 4 magic + 1 version + 4 count = 9 bytes
    let mut header = [0u8; 9];
    reader
        .read_exact(&mut header)
        .map_err(|_| MonitorError::InvalidIndex("truncated header".to_string()))?;

    if &header[0..4] != MAGIC {
        return Err(MonitorError::InvalidIndex(format!(
            "bad magic: {:?}",
            &header[0..4]
        )));
    }

    if header[4] != VERSION {
        return Err(MonitorError::InvalidIndex(format!(
            "unsupported version: {}",
            header[4]
        )));
    }

    let count = u32::from_le_bytes([header[5], header[6], header[7], header[8]]) as usize;
    let mut map = HashMap::with_capacity(count);

    for _ in 0..count {
        // Read hash (8 bytes)
        let mut hash_buf = [0u8; 8];
        reader
            .read_exact(&mut hash_buf)
            .map_err(|_| MonitorError::InvalidIndex("truncated record: hash".to_string()))?;
        let hash = u64::from_le_bytes(hash_buf);

        // Read len (2 bytes)
        let mut len_buf = [0u8; 2];
        reader
            .read_exact(&mut len_buf)
            .map_err(|_| MonitorError::InvalidIndex("truncated record: len".to_string()))?;
        let domain_len = u16::from_le_bytes(len_buf) as usize;

        // Read domain bytes
        let mut domain_buf = vec![0u8; domain_len];
        reader
            .read_exact(&mut domain_buf)
            .map_err(|_| MonitorError::InvalidIndex("truncated record: domain".to_string()))?;

        let domain = String::from_utf8(domain_buf)
            .map_err(|e| MonitorError::InvalidIndex(format!("invalid UTF-8 domain: {e}")))?;

        map.insert(hash, domain);
    }

    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_index(entries: &[(u64, &str)]) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();

        // Header
        file.write_all(b"DGHI").unwrap();
        file.write_all(&[0x01]).unwrap();
        file.write_all(&(entries.len() as u32).to_le_bytes())
            .unwrap();

        // Records
        for (hash, domain) in entries {
            let domain_bytes = domain.as_bytes();
            file.write_all(&hash.to_le_bytes()).unwrap();
            file.write_all(&(domain_bytes.len() as u16).to_le_bytes())
                .unwrap();
            file.write_all(domain_bytes).unwrap();
        }

        file.flush().unwrap();
        file
    }

    #[test]
    fn test_valid_index_roundtrip() {
        let entries = vec![
            (0xdeadbeef_u64, "example.com"),
            (0xcafebabe_u64, "test.org"),
            (0x12345678_u64, "foo.net"),
        ];
        let file = write_index(&entries);
        let map = read_host_index(file.path().to_str().unwrap()).unwrap();

        assert_eq!(map.len(), 3);
        assert_eq!(map[&0xdeadbeef], "example.com");
        assert_eq!(map[&0xcafebabe], "test.org");
        assert_eq!(map[&0x12345678], "foo.net");
    }

    #[test]
    fn test_empty_index_succeeds() {
        let file = write_index(&[]);
        let map = read_host_index(file.path().to_str().unwrap()).unwrap();
        assert!(map.is_empty());
    }

    #[test]
    fn test_wrong_magic() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"XXXX").unwrap();
        file.write_all(&[0x01]).unwrap();
        file.write_all(&0u32.to_le_bytes()).unwrap();
        file.flush().unwrap();

        let result = read_host_index(file.path().to_str().unwrap());
        assert!(matches!(result, Err(MonitorError::InvalidIndex(_))));
    }

    #[test]
    fn test_wrong_version() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"DGHI").unwrap();
        file.write_all(&[0x02]).unwrap(); // wrong version
        file.write_all(&0u32.to_le_bytes()).unwrap();
        file.flush().unwrap();

        let result = read_host_index(file.path().to_str().unwrap());
        assert!(matches!(result, Err(MonitorError::InvalidIndex(_))));
    }

    #[test]
    fn test_truncated_record() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        // Header says 1 record, but we provide none
        file.write_all(b"DGHI").unwrap();
        file.write_all(&[0x01]).unwrap();
        file.write_all(&1u32.to_le_bytes()).unwrap();
        // No record data
        file.flush().unwrap();

        let result = read_host_index(file.path().to_str().unwrap());
        assert!(matches!(result, Err(MonitorError::InvalidIndex(_))));
    }
}
