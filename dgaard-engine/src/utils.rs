use std::fs::{File, OpenOptions};
use std::io::BufWriter;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Count the number of dots in a domain name.
/// This gives the subdomain depth (e.g., "example.com" → 1, "sub.example.com" → 2).
pub fn count_dots(domain: &str) -> u8 {
    domain.bytes().filter(|&b| b == b'.').count() as u8
}

/// Canonical form of a list entry: ASCII-lowercased, without trailing root dot.
/// Queries reach the matcher lowercased and dotless, so entries must match.
pub fn normalize_domain(domain: &str) -> String {
    domain.trim_end_matches('.').to_ascii_lowercase()
}

/// Permissions of the files dgaard writes: readable by the dashboard and
/// other tools, writable by the daemon only.
#[cfg(unix)]
const WRITTEN_FILE_MODE: u32 = 0o644;

/// Replace `path` with what `write` produces, atomically and without
/// following links planted by another user — dgaard often runs as root.
///
/// The data goes to a fresh, uniquely named file next to `path`, created
/// with `O_CREAT | O_EXCL` (an existing file or symlink under that name is
/// an error, never a write target), flushed and synced, then renamed over
/// `path`. Readers see the old file or the new one, never half of it; a
/// symlink at `path` is replaced itself, not written through. On any
/// error the temporary file is removed and `path` is left untouched. A
/// missing parent directory is created.
pub fn write_atomic<F>(path: &Path, write: F) -> std::io::Result<()>
where
    F: FnOnce(&mut BufWriter<File>) -> std::io::Result<()>,
{
    let dir = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    std::fs::create_dir_all(dir)?;

    let tmp = temp_path_for(path, dir)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, WRITTEN_FILE_MODE);
    let file = options.open(&tmp)?;

    let result = (|| {
        let mut writer = BufWriter::new(file);
        write(&mut writer)?;
        let file = writer.into_inner().map_err(|e| e.into_error())?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
        return result;
    }

    // Persist the rename itself; best effort, not every platform allows
    // syncing a directory.
    if let Ok(dir_handle) = File::open(dir) {
        let _ = dir_handle.sync_all();
    }
    Ok(())
}

/// `.<name>.<pid>.<n>.tmp` in `dir`: hidden, unique per process and call.
fn temp_path_for(path: &Path, dir: &Path) -> std::io::Result<PathBuf> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let name = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} has no file name", path.display()),
        )
    })?;
    let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
    Ok(dir.join(format!(
        ".{}.{}.{unique}.tmp",
        name.to_string_lossy(),
        std::process::id()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_count_dots() {
        assert_eq!(count_dots("tld"), 0);
        assert_eq!(count_dots("example.org"), 1);
        assert_eq!(count_dots("with.sub.domains.end"), 3);
    }

    #[test]
    fn test_normalize_domain() {
        assert_eq!(normalize_domain("Tracker.COM"), "tracker.com");
        assert_eq!(normalize_domain("example.com."), "example.com");
        assert_eq!(normalize_domain("already.ok"), "already.ok");
    }

    // ---- write_atomic (review F15) ----

    fn entries(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn write_atomic_creates_and_replaces_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.bin");
        write_atomic(&path, |w| w.write_all(b"first")).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
        write_atomic(&path, |w| w.write_all(b"second")).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second");
        assert_eq!(entries(dir.path()), ["out.bin"], "no temp file left");
    }

    #[test]
    fn write_atomic_creates_the_parent_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a/b/out.bin");
        write_atomic(&path, |w| w.write_all(b"x")).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"x");
    }

    #[test]
    fn write_atomic_failure_keeps_the_old_file_and_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.bin");
        std::fs::write(&path, b"old").unwrap();
        let err = write_atomic(&path, |w| {
            w.write_all(b"partial")?;
            Err(std::io::Error::other("writer failed"))
        })
        .unwrap_err();
        assert_eq!(err.to_string(), "writer failed");
        assert_eq!(std::fs::read(&path).unwrap(), b"old");
        assert_eq!(entries(dir.path()), ["out.bin"], "temp file removed");
    }

    #[test]
    fn write_atomic_rejects_a_path_without_file_name() {
        let dir = tempfile::tempdir().unwrap();
        assert!(write_atomic(&dir.path().join(".."), |_| Ok(())).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn write_atomic_replaces_a_symlink_instead_of_writing_through_it() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"precious").unwrap();
        let path = dir.path().join("out.bin");
        std::os::unix::fs::symlink(&victim, &path).unwrap();

        write_atomic(&path, |w| w.write_all(b"new")).unwrap();
        assert_eq!(std::fs::read(&victim).unwrap(), b"precious");
        assert!(!std::fs::symlink_metadata(&path).unwrap().is_symlink());
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
    }

    #[cfg(unix)]
    #[test]
    fn write_atomic_file_is_not_group_or_world_writable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.bin");
        write_atomic(&path, |w| w.write_all(b"x")).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o022, 0, "mode {mode:o}");
    }
}
