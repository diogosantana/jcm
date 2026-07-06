use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use which::which;

use crate::DEFAULT_STORE_PASS;
use crate::cli::GlobalOpts;

#[derive(Clone, Debug)]
pub struct JvmInfo {
    pub java_home: PathBuf,
    pub cacerts: PathBuf,
    /// Use `keytool -cacerts` instead of `-keystore <path>` (required on newer JDKs).
    pub use_system_cacerts: bool,
    pub store_pass: String,
    pub java_bin: PathBuf,
    pub keytool_bin: PathBuf,
}

pub fn resolve_jvm(opts: &GlobalOpts) -> Result<JvmInfo> {
    let store_pass = opts
        .store_pass
        .clone()
        .unwrap_or_else(|| DEFAULT_STORE_PASS.to_string());

    if let Some(cacerts) = &opts.cacerts {
        let java_home = opts
            .java_home
            .clone()
            .or_else(detect_java_home)
            .unwrap_or_else(|| PathBuf::from("."));
        return Ok(build_info(
            java_home,
            cacerts.clone(),
            store_pass,
        )?);
    }

    let java_home = if let Some(h) = &opts.java_home {
        h.clone()
    } else {
        detect_java_home().context(
            "could not detect JAVA_HOME; set --java-home or JAVA_HOME environment variable",
        )?
    };

    let cacerts = java_home.join("lib").join("security").join("cacerts");
    if !cacerts.exists() {
        bail!(
            "cacerts not found at {}; set --cacerts or --java-home",
            cacerts.display()
        );
    }
    build_info(java_home, cacerts, store_pass)
}

fn build_info(java_home: PathBuf, cacerts: PathBuf, store_pass: String) -> Result<JvmInfo> {
    let java_bin = which_java_in_home(&java_home)?;
    let keytool_bin = which_keytool_in_home(&java_home)?;
    let use_system_cacerts = is_system_cacerts(&java_home, &cacerts);
    Ok(JvmInfo {
        java_home,
        cacerts,
        use_system_cacerts,
        store_pass,
        java_bin,
        keytool_bin,
    })
}

fn is_system_cacerts(java_home: &Path, cacerts: &Path) -> bool {
    let default = java_home.join("lib").join("security").join("cacerts");
    same_path(cacerts, &default)
}

fn same_path(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

pub fn detect_java_home() -> Option<PathBuf> {
    if let Ok(h) = env::var("JAVA_HOME") {
        return Some(PathBuf::from(h));
    }
    parse_java_home_property().or_else(platform_java_home)
}

fn parse_java_home_property() -> Option<PathBuf> {
    let java = which("java").ok()?;
    let output = Command::new(java)
        .arg("-XshowSettings:properties")
        .arg("-version")
        .output()
        .ok()?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    for line in stderr.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("java.home = ") {
            return Some(PathBuf::from(rest.trim()));
        }
    }
    None
}

fn platform_java_home() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("/usr/libexec/java_home").output().ok()?;
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Some(PathBuf::from(path));
            }
        }
    }
    #[cfg(unix)]
    {
        if let Ok(java) = which("java") {
            if let Ok(real) = std::fs::canonicalize(&java) {
                if let Some(bin) = real.parent() {
                    if let Some(home) = bin.parent() {
                        return Some(home.to_path_buf());
                    }
                }
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Ok(java) = which("java") {
            if let Some(bin) = java.parent() {
                if let Some(home) = bin.parent() {
                    return Some(home.to_path_buf());
                }
            }
        }
    }
    None
}

fn which_java_in_home(home: &Path) -> Result<PathBuf> {
    let candidate = home.join("bin").join(exe_name("java"));
    if candidate.exists() {
        return Ok(candidate);
    }
    which("java").context("java not found in PATH")
}

fn which_keytool_in_home(home: &Path) -> Result<PathBuf> {
    let candidate = home.join("bin").join(exe_name("keytool"));
    if candidate.exists() {
        return Ok(candidate);
    }
    which("keytool").context("keytool not found in PATH")
}

fn exe_name(name: &str) -> String {
    if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_string()
    }
}

pub fn doctor_jvm_report(info: &JvmInfo) -> Vec<String> {
    vec![
        format!("java.home: {}", info.java_home.display()),
        format!("cacerts: {}", info.cacerts.display()),
        format!(
            "keytool target: {}",
            if info.use_system_cacerts {
                "-cacerts"
            } else {
                "-keystore"
            }
        ),
        format!("java: {}", info.java_bin.display()),
        format!("keytool: {}", info.keytool_bin.display()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_default_cacerts_path() {
        let home = PathBuf::from("/opt/jdk");
        let cacerts = home.join("lib").join("security").join("cacerts");
        assert!(is_system_cacerts(&home, &cacerts));
    }

    #[test]
    fn custom_cacerts_is_not_system() {
        let home = PathBuf::from("/opt/jdk");
        let cacerts = PathBuf::from("/tmp/my-cacerts");
        assert!(!is_system_cacerts(&home, &cacerts));
    }
}
