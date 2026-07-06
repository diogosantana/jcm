use std::process::Command;

#[test]
fn add_from_env_vars() {
    let bin = env!("CARGO_BIN_EXE_jcm");
    let output = Command::new(bin)
        .env("JCM_ALIAS", "env-test")
        .env("JCM_URL", "https://example.com")
        .env("JCM_DRY_RUN", "1")
        .arg("add")
        .output()
        .expect("run add from env");
    assert!(
        output.status.success() || output.status.code() == Some(3),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn cli_overrides_env_alias() {
    let bin = env!("CARGO_BIN_EXE_jcm");
    let output = Command::new(bin)
        .env("JCM_ALIAS", "from-env")
        .env("JCM_URL", "https://example.com")
        .env("JCM_DRY_RUN", "1")
        .args(["add", "from-cli", "https://example.com"])
        .output()
        .expect("run add with cli override");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("from-cli") && !stdout.contains("from-env"),
        "stdout: {stdout}"
    );
}

#[test]
fn global_chain_from_env() {
    let bin = env!("CARGO_BIN_EXE_jcm");
    let output = Command::new(bin)
        .env("JCM_URL", "https://example.com")
        .env("JCM_CHAIN", "leaf")
        .arg("inspect")
        .output()
        .expect("run inspect from env");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("chain=leaf"), "stdout: {stdout}");
}
