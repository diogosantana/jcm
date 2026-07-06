use std::collections::{HashMap, HashSet};
use std::path::Path;

use anyhow::{Result, bail};
use tracing::info;

use crate::cli::GlobalOpts;
use crate::elevation::{ElevationPlan, run_command_with_env};
use crate::jvm::JvmInfo;
use crate::logging::LogMode;

#[derive(Clone, Debug)]
pub struct KeystoreEntry {
    pub alias: String,
    pub fingerprint_sha256: Option<String>,
    pub managed: bool,
}

pub fn list_entries(
    jvm: &JvmInfo,
    prefix: &str,
    log: LogMode,
) -> Result<Vec<KeystoreEntry>> {
    // Listing is read-only; cacerts is world-readable and does not need elevation.
    // Avoid `-v` — JDK 25 already prints SHA-256 fingerprints in the default list output.
    let output = run_keytool(jvm, &["-list"], ElevationPlan::Direct, log)?;
    if !output.status.success() {
        bail!("{}", format_keytool_failure("keytool list failed", &output));
    }
    Ok(parse_keytool_list(
        &String::from_utf8_lossy(&output.stdout),
        prefix,
    ))
}

fn parse_keytool_list(text: &str, prefix: &str) -> Vec<KeystoreEntry> {
    let mut entries = Vec::new();
    let mut current_alias: Option<String> = None;
    let mut current_fp: Option<String> = None;

    for line in text.lines() {
        let line = line.trim();
        if let Some(alias) = line.strip_prefix("Alias name:") {
            push_entry(&mut entries, current_alias.take(), current_fp.take());
            current_alias = Some(alias.trim().to_string());
            current_fp = None;
        } else if let Some(fp) = parse_sha256_fingerprint(line) {
            current_fp = Some(fp);
        } else if let Some(alias) = parse_compact_alias_line(line) {
            push_entry(&mut entries, current_alias.take(), current_fp.take());
            current_alias = Some(alias);
            current_fp = None;
        }
    }
    push_entry(&mut entries, current_alias.take(), current_fp.take());

    for e in &mut entries {
        e.managed = e.alias.starts_with(prefix);
    }
    entries
}

fn push_entry(
    entries: &mut Vec<KeystoreEntry>,
    alias: Option<String>,
    fingerprint_sha256: Option<String>,
) {
    if let Some(alias) = alias {
        entries.push(KeystoreEntry {
            alias,
            fingerprint_sha256,
            managed: false,
        });
    }
}

fn parse_compact_alias_line(line: &str) -> Option<String> {
    if line.is_empty()
        || line.starts_with("Keystore ")
        || line.starts_with("Your keystore")
        || line.starts_with("Certificate ")
        || line.starts_with('*')
        || !line_contains_entry_type(line)
    {
        return None;
    }
    let head = line.split(',').next()?.trim();
    if head.is_empty() || head.contains("fingerprint") || !is_plausible_alias_name(head) {
        return None;
    }
    Some(head.to_string())
}

/// keytool entry types stay in English regardless of JVM locale.
fn line_contains_entry_type(line: &str) -> bool {
    line.contains("trustedCertEntry")
        || line.contains("PrivateKeyEntry")
        || line.contains("SecretKeyEntry")
}

fn is_plausible_alias_name(alias: &str) -> bool {
    if alias.is_empty() || alias.len() > 120 {
        return false;
    }
    let lower = alias.to_ascii_lowercase();
    !(lower.contains("keystore")
        || lower.contains("contains")
        || lower.contains("entrad")
        || lower.contains("armazenamento")
        || lower.contains("contém")
        || lower.contains("contem"))
}

fn parse_sha256_fingerprint(line: &str) -> Option<String> {
    line.strip_prefix("SHA256:")
        .or_else(|| line.strip_prefix("Certificate fingerprint (SHA-256):"))
        .map(|fp| fp.trim().to_uppercase())
}

pub fn import_cert(
    jvm: &JvmInfo,
    alias: &str,
    pem_path: &Path,
    plan: ElevationPlan,
    log: LogMode,
) -> Result<()> {
    if crate::logging::info_enabled(log) {
        info!("importing {alias} from {}", pem_path.display());
    }
    let file = pem_path.to_str().unwrap();
    let output = run_keytool(
        jvm,
        &["-importcert", "-noprompt", "-alias", alias, "-file", file],
        plan,
        log,
    )?;
    if !output.status.success() {
        bail!(
            "{}",
            format_keytool_failure(&format!("keytool import failed for {alias}"), &output)
        );
    }
    Ok(())
}

pub fn delete_alias(
    jvm: &JvmInfo,
    alias: &str,
    plan: ElevationPlan,
    log: LogMode,
) -> Result<()> {
    if crate::logging::info_enabled(log) {
        info!("deleting keystore alias {alias}");
    }
    let output = run_keytool(jvm, &["-delete", "-alias", alias], plan, log)?;
    if !output.status.success() {
        let detail = format_keytool_failure("keytool delete failed", &output);
        if detail.contains("does not exist") {
            return Ok(());
        }
        bail!("{detail} (alias: {alias})");
    }
    Ok(())
}

pub fn verify_builtin_aliases_unchanged(
    before: &[KeystoreEntry],
    after: &[KeystoreEntry],
    managed_prefix: &str,
) -> Result<()> {
    let after_set = alias_set(after);
    for entry in before {
        if entry.alias.starts_with(managed_prefix) {
            continue;
        }
        if !is_plausible_alias_name(&entry.alias) {
            continue;
        }
        if !after_set.contains(entry.alias.as_str()) {
            bail!("built-in alias missing from cacerts after operation: {}", entry.alias);
        }
    }
    Ok(())
}

pub fn fingerprint_map(entries: &[KeystoreEntry]) -> HashMap<String, String> {
    entries
        .iter()
        .filter_map(|e| e.fingerprint_sha256.clone().map(|fp| (e.alias.clone(), fp)))
        .collect()
}

pub fn alias_set(entries: &[KeystoreEntry]) -> HashSet<String> {
    entries.iter().map(|e| e.alias.clone()).collect()
}

pub fn show_alias(
    jvm: &JvmInfo,
    alias: &str,
    log: LogMode,
) -> Result<String> {
    let output = run_keytool(
        jvm,
        &["-list", "-v", "-alias", alias],
        ElevationPlan::Direct,
        log,
    )?;
    if !output.status.success() {
        bail!("{}", format_keytool_failure(&format!("keytool show failed for {alias}"), &output));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

pub fn keystore_alias_for(config_alias: &str, opts: &GlobalOpts) -> String {
    format!("{}{}", opts.alias_prefix, config_alias)
}

fn run_keytool(
    jvm: &JvmInfo,
    command_args: &[&str],
    plan: ElevationPlan,
    log: LogMode,
) -> Result<std::process::Output> {
    let java_home = jvm.java_home.to_string_lossy().into_owned();
    let env = [("JAVA_HOME", java_home.as_str())];

    let primary = run_keytool_with_target(jvm, command_args, plan, log, jvm.use_system_cacerts, &env)?;
    if primary.status.success() {
        return Ok(primary);
    }

    if jvm.use_system_cacerts {
        let fallback =
            run_keytool_with_target(jvm, command_args, plan, log, false, &env)?;
        if fallback.status.success() {
            return Ok(fallback);
        }
        bail!(
            "{}",
            format_keytool_failure(
                "keytool failed (tried -cacerts and -keystore)",
                &primary,
            )
        );
    }

    bail!("{}", format_keytool_failure("keytool failed", &primary));
}

fn run_keytool_with_target(
    jvm: &JvmInfo,
    command_args: &[&str],
    plan: ElevationPlan,
    log: LogMode,
    use_cacerts_flag: bool,
    env: &[(&str, &str)],
) -> Result<std::process::Output> {
    let mut args: Vec<String> = command_args.iter().map(|s| (*s).to_string()).collect();
    push_keystore_target_args(jvm, &mut args, use_cacerts_flag);
    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    run_command_with_env(&jvm.keytool_bin, &arg_refs, plan, log, env)
}

fn push_keystore_target_args(jvm: &JvmInfo, args: &mut Vec<String>, use_cacerts_flag: bool) {
    if use_cacerts_flag {
        args.push("-cacerts".to_string());
    } else {
        args.push("-keystore".to_string());
        args.push(jvm.cacerts.to_string_lossy().into_owned());
    }
    args.push("-storepass".to_string());
    args.push(jvm.store_pass.clone());
}

fn format_keytool_failure(label: &str, output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let status = output
        .status
        .code()
        .map(|code| code.to_string())
        .unwrap_or_else(|| format!("{:?}", output.status));

    let mut msg = format!("{label} (exit {status})");
    if !stderr.trim().is_empty() {
        msg.push_str(&format!("\nstderr: {}", stderr.trim()));
    }
    if !stdout.trim().is_empty() {
        let snippet: String = stdout.chars().take(500).collect();
        msg.push_str(&format!("\nstdout: {snippet}"));
        if stdout.len() > 500 {
            msg.push_str("...");
        }
    }
    if stderr.trim().is_empty() && stdout.trim().is_empty() {
        msg.push_str("\n(no output captured)");
    }
    msg
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_jvm(use_system_cacerts: bool) -> JvmInfo {
        JvmInfo {
            java_home: PathBuf::from("/opt/jdk"),
            cacerts: PathBuf::from("/opt/jdk/lib/security/cacerts"),
            use_system_cacerts,
            store_pass: "changeit".to_string(),
            java_bin: PathBuf::from("/opt/jdk/bin/java"),
            keytool_bin: PathBuf::from("/opt/jdk/bin/keytool"),
        }
    }

    #[test]
    fn system_cacerts_uses_cacerts_flag() {
        let mut args = vec!["-list".to_string()];
        push_keystore_target_args(&test_jvm(true), &mut args, true);
        assert_eq!(
            args,
            vec!["-list", "-cacerts", "-storepass", "changeit"]
        );
    }

    #[test]
    fn custom_keystore_uses_keystore_flag() {
        let mut args = vec!["-list".to_string()];
        push_keystore_target_args(&test_jvm(false), &mut args, false);
        assert_eq!(
            args,
            vec![
                "-list",
                "-keystore",
                "/opt/jdk/lib/security/cacerts",
                "-storepass",
                "changeit"
            ]
        );
    }

    #[test]
    fn parses_jdk25_compact_list_output() {
        let sample = r#"Keystore type: PKCS12

actalisauthenticationrootca [jdk], 2 Jul 2026, trustedCertEntry,
Certificate fingerprint (SHA-256): aa:bb:cc:dd
jcm-example, 2 Jul 2026, trustedCertEntry,
Certificate fingerprint (SHA-256): 11:22:33:44
"#;
        let entries = parse_keytool_list(sample, "jcm-");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].alias, "actalisauthenticationrootca [jdk]");
        assert_eq!(entries[0].fingerprint_sha256.as_deref(), Some("AA:BB:CC:DD"));
        assert!(!entries[0].managed);
        assert_eq!(entries[1].alias, "jcm-example");
        assert!(entries[1].managed);
    }

    #[test]
    fn ignores_localized_keystore_summary_line() {
        let sample = r#"Keystore type: PKCS12

Sua área de armazenamento de chaves contém 109 entradas

actalisauthenticationrootca [jdk], 2 Jul 2026, trustedCertEntry,
Certificate fingerprint (SHA-256): aa:bb:cc:dd
"#;
        let entries = parse_keytool_list(sample, "jcm-");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].alias, "actalisauthenticationrootca [jdk]");
    }

    #[test]
    fn verify_builtin_skips_managed_aliases() {
        let before = vec![
            KeystoreEntry {
                alias: "actalisauthenticationrootca [jdk]".to_string(),
                fingerprint_sha256: None,
                managed: false,
            },
            KeystoreEntry {
                alias: "jcm-api".to_string(),
                fingerprint_sha256: None,
                managed: true,
            },
        ];
        let after = vec![KeystoreEntry {
            alias: "actalisauthenticationrootca [jdk]".to_string(),
            fingerprint_sha256: None,
            managed: false,
        }];
        verify_builtin_aliases_unchanged(&before, &after, "jcm-").expect("verify");
    }

    #[test]
    fn verify_builtin_fails_when_ca_removed() {
        let before = vec![KeystoreEntry {
            alias: "actalisauthenticationrootca [jdk]".to_string(),
            fingerprint_sha256: None,
            managed: false,
        }];
        let after = vec![];
        assert!(verify_builtin_aliases_unchanged(&before, &after, "jcm-").is_err());
    }

    #[test]
    fn verify_builtin_ignores_localized_summary_line() {
        let before = vec![
            KeystoreEntry {
                alias: "Sua área de armazenamento de chaves contém 109 entradas".to_string(),
                fingerprint_sha256: None,
                managed: false,
            },
            KeystoreEntry {
                alias: "actalisauthenticationrootca [jdk]".to_string(),
                fingerprint_sha256: None,
                managed: false,
            },
        ];
        let after = vec![KeystoreEntry {
            alias: "actalisauthenticationrootca [jdk]".to_string(),
            fingerprint_sha256: None,
            managed: false,
        }];
        verify_builtin_aliases_unchanged(&before, &after, "jcm-").expect("verify");
    }

    #[test]
    fn parses_verbose_alias_output() {
        let sample = r#"Alias name: jcm-test
SHA256: AA:BB:CC
"#;
        let entries = parse_keytool_list(sample, "jcm-");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].alias, "jcm-test");
        assert_eq!(entries[0].fingerprint_sha256.as_deref(), Some("AA:BB:CC"));
        assert!(entries[0].managed);
    }

    #[test]
    fn failure_message_includes_stdout_when_stderr_empty() {
        let output = std::process::Command::new(env!("CARGO"))
            .arg("__jcm_test_nonexistent_subcommand__")
            .output()
            .expect("spawn cargo");
        let mut output = output;
        output.stdout = b"keytool error: bad password\n".to_vec();
        output.stderr.clear();
        let msg = format_keytool_failure("keytool list failed", &output);
        assert!(msg.contains("keytool list failed"));
        assert!(msg.contains("bad password"));
    }
}
