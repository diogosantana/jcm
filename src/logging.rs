use std::path::Path;

use tracing_subscriber::filter::LevelFilter;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LogMode {
    #[default]
    Normal,
    Quiet,
    Verbose,
}

pub fn init(mode: LogMode) {
    let level = match mode {
        LogMode::Quiet => LevelFilter::ERROR,
        LogMode::Normal => LevelFilter::INFO,
        LogMode::Verbose => LevelFilter::DEBUG,
    };
    let _ = tracing_subscriber::fmt()
        .with_max_level(level)
        .with_target(false)
        .try_init();
}

pub fn info_enabled(mode: LogMode) -> bool {
    matches!(mode, LogMode::Normal | LogMode::Verbose)
}

pub fn debug_enabled(mode: LogMode) -> bool {
    matches!(mode, LogMode::Verbose)
}

/// Format an external command for verbose logging. Redacts values after `-storepass`.
pub fn format_external_command(program: &Path, args: &[&str], wrapper: &[&str]) -> String {
    let mut parts: Vec<String> = wrapper.iter().map(|s| (*s).to_string()).collect();
    parts.push(shell_quote(program.to_string_lossy().as_ref()));
    parts.extend(redact_sensitive_args(args).into_iter().map(|a| shell_quote(&a)));
    parts.join(" ")
}

fn shell_quote(arg: &str) -> String {
    if arg.is_empty() {
        return "''".to_string();
    }
    if arg
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "./_:-@".contains(c))
    {
        arg.to_string()
    } else {
        format!("'{}'", arg.replace('\'', "'\\''"))
    }
}

fn redact_sensitive_args(args: &[&str]) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len());
    let mut redact_next = false;
    for arg in args {
        if redact_next {
            out.push("***".to_string());
            redact_next = false;
            continue;
        }
        if matches!(
            *arg,
            "-storepass" | "-deststorepass" | "-srcstorepass" | "-keypass"
        ) {
            out.push(arg.to_string());
            redact_next = true;
            continue;
        }
        out.push(arg.to_string());
    }
    out
}

pub fn log_external_command(log: LogMode, program: &Path, args: &[&str], wrapper: &[&str]) {
    if debug_enabled(log) {
        tracing::debug!("exec: {}", format_external_command(program, args, wrapper));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn redacts_storepass_in_command_display() {
        let cmd = format_external_command(
            Path::new("/usr/bin/keytool"),
            &["-list", "-storepass", "secret", "-keystore", "/tmp/cacerts"],
            &[],
        );
        assert!(cmd.contains("-storepass"));
        assert!(cmd.contains("***"));
        assert!(!cmd.contains("secret"));
    }
}
