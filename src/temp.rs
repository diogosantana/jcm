use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};

/// Per-run scratch directory under the OS temp folder; removed on drop.
pub struct TempWorkspace {
    dir: PathBuf,
}

impl TempWorkspace {
    pub fn new() -> Result<Self> {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("jcm-{}-{}", std::process::id(), stamp));
        fs::create_dir_all(&dir).with_context(|| format!("create temp dir {}", dir.display()))?;
        Ok(Self { dir })
    }

    pub fn path(&self) -> &Path {
        &self.dir
    }

    pub fn write_pem(&self, name: &str, pem: &str) -> Result<PathBuf> {
        let file = self.dir.join(format!("{name}.pem"));
        fs::write(&file, pem).with_context(|| format!("write temp pem {}", file.display()))?;
        Ok(file)
    }
}

impl Drop for TempWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}
