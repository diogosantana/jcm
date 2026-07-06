use std::env;
use std::fs::OpenOptions;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

use crate::cli::ElevateMode;
use crate::logging::LogMode;
use crate::platform::{is_interactive_tty, is_root};

pub const ELEVATED_ENV: &str = "JCM_ELEVATED";

pub fn is_elevated() -> bool {
    env::var(ELEVATED_ENV).ok().as_deref() == Some("1") || is_root()
}

pub fn cacerts_writable(path: &Path) -> bool {
    if !path.exists() {
        return false;
    }
    OpenOptions::new().write(true).append(true).open(path).is_ok()
}

pub fn ensure_can_mutate(
    cacerts: &Path,
    mode: ElevateMode,
    log: LogMode,
) -> Result<ElevationPlan> {
    let writable = cacerts_writable(cacerts);
    match mode {
        ElevateMode::Never if !writable => {
            bail!(
                "cacerts is not writable: {} (use --elevate auto or --cacerts with a writable copy)",
                cacerts.display()
            );
        }
        ElevateMode::Always if !writable && !is_elevated() => {
            return Ok(ElevationPlan::NeedElevation);
        }
        ElevateMode::Auto if !writable && !is_elevated() => {
            if crate::logging::info_enabled(log) {
                tracing::info!(
                    "cacerts requires elevated permissions: {}",
                    cacerts.display()
                );
            }
            return Ok(ElevationPlan::NeedElevation);
        }
        _ => {}
    }
    Ok(if writable || is_elevated() {
        ElevationPlan::Direct
    } else {
        ElevationPlan::NeedElevation
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ElevationPlan {
    Direct,
    NeedElevation,
}

pub fn run_command(
    program: &Path,
    args: &[&str],
    plan: ElevationPlan,
    log: LogMode,
) -> Result<std::process::Output> {
    run_command_with_env(program, args, plan, log, &[])
}

pub fn run_command_with_env(
    program: &Path,
    args: &[&str],
    plan: ElevationPlan,
    log: LogMode,
    extra_env: &[(&str, &str)],
) -> Result<std::process::Output> {
    match plan {
        ElevationPlan::Direct => run_process(program, args, false, log, extra_env),
        ElevationPlan::NeedElevation => {
            #[cfg(unix)]
            {
                run_elevated_unix(program, args, log, extra_env)
            }
            #[cfg(windows)]
            {
                let _ = (program, args, log, extra_env);
                bail!("Windows elevation requires relaunching jcm; use elevated terminal or --elevate auto")
            }
            #[cfg(not(any(unix, windows)))]
            {
                let _ = extra_env;
                bail!("elevation not supported on this platform")
            }
        }
    }
}

fn run_process(
    program: &Path,
    args: &[&str],
    via_sudo: bool,
    log: LogMode,
    extra_env: &[(&str, &str)],
) -> Result<std::process::Output> {
    let wrapper = if via_sudo { &["sudo", "-E"][..] } else { &[][..] };
    crate::logging::log_external_command(log, program, args, wrapper);

    let mut cmd = if via_sudo {
        let mut c = Command::new("sudo");
        c.arg("-E").arg(program);
        c.args(args);
        c
    } else {
        let mut c = Command::new(program);
        c.args(args);
        c
    };
    cmd.env(ELEVATED_ENV, "1");
    for (key, value) in extra_env {
        cmd.env(key, value);
    }
    let output = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .with_context(|| format!("run {}", program.display()))?;
    Ok(output)
}

#[cfg(unix)]
fn run_elevated_unix(
    program: &Path,
    args: &[&str],
    log: LogMode,
    extra_env: &[(&str, &str)],
) -> Result<std::process::Output> {
    if which::which("sudo").is_err() {
        bail!("sudo not found; cannot elevate to modify cacerts");
    }
    let non_interactive = run_process(program, args, true, log, extra_env);
    if let Ok(out) = &non_interactive {
        if out.status.success() {
            return non_interactive;
        }
    }
    if !is_interactive_tty() {
        bail!("cacerts is not writable and no cached sudo credentials (non-interactive session)");
    }
    if crate::logging::info_enabled(log) {
        tracing::info!("requesting administrator password via sudo...");
    }
    run_process(program, args, true, log, extra_env)
}

pub fn copy_file_elevated(from: &Path, to: &Path, plan: ElevationPlan, log: LogMode) -> Result<()> {
    match plan {
        ElevationPlan::Direct => {
            if crate::logging::debug_enabled(log) {
                tracing::debug!("exec: cp {} {}", from.display(), to.display());
            }
            std::fs::copy(from, to).with_context(|| format!("copy {} -> {}", from.display(), to.display()))?;
            Ok(())
        }
        ElevationPlan::NeedElevation => {
            #[cfg(unix)]
            {
                if which::which("sudo").is_err() {
                    bail!("sudo not found");
                }
                if crate::logging::debug_enabled(log) {
                    let from_s = from.to_string_lossy().into_owned();
                    let to_s = to.to_string_lossy().into_owned();
                    tracing::debug!(
                        "exec: {}",
                        crate::logging::format_external_command(
                            Path::new("cp"),
                            &[from_s.as_str(), to_s.as_str()],
                            &["sudo"],
                        )
                    );
                }
                let status = Command::new("sudo")
                    .arg("cp")
                    .arg(from)
                    .arg(to)
                    .status()
                    .context("sudo cp")?;
                if !status.success() {
                    bail!("sudo cp failed with status {status}");
                }
                Ok(())
            }
            #[cfg(windows)]
            {
                let _ = (from, to, log);
                bail!("elevated file copy on Windows requires elevated jcm process")
            }
            #[cfg(not(any(unix, windows)))]
            {
                bail!("elevated copy not supported")
            }
        }
    }
}

pub fn prepare_mutation(
    cacerts: &Path,
    mode: ElevateMode,
    log: LogMode,
) -> Result<ElevationPlan> {
    let plan = ensure_can_mutate(cacerts, mode, log)?;
    #[cfg(windows)]
    if matches!(plan, ElevationPlan::NeedElevation) {
        relaunch_self_elevated(std::env::args().collect(), log)?;
    }
    Ok(plan)
}

#[cfg(windows)]
fn forward_jcm_env(cmd: &mut runas::Command) {
    for (key, value) in env::vars().filter(|(k, _)| k.starts_with("JCM_") || k == "JAVA_HOME") {
        cmd.env(key, value);
    }
}

#[cfg(windows)]
fn relaunch_self_elevated(args: Vec<String>, log: LogMode) -> Result<()> {
    use anyhow::Context;
    if is_elevated() {
        return Ok(());
    }
    if crate::logging::info_enabled(log) {
        tracing::info!("requesting administrator privileges (UAC)...");
    }
    let exe = std::env::current_exe().context("current exe")?;
    let mut cmd = runas::Command::new(exe);
    for arg in args.iter().skip(1) {
        cmd.arg(arg);
    }
    cmd.env(ELEVATED_ENV, "1");
    forward_jcm_env(&mut cmd);
    let status = cmd.status().context("elevated relaunch")?;
    std::process::exit(status.code().unwrap_or(1));
}

pub fn doctor_elevation_report() -> Vec<String> {
    let mut lines = vec![format!("elevated process: {}", is_elevated())];
    #[cfg(unix)]
    {
        lines.push(format!("sudo available: {}", which::which("sudo").is_ok()));
    }
    lines.push(format!("interactive tty: {}", is_interactive_tty()));
    lines
}
