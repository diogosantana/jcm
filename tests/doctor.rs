use std::process::Command;

#[test]
fn list_runs() {
    let bin = env!("CARGO_BIN_EXE_jcm");
    let output = Command::new(bin).arg("list").output().expect("run list");
    assert!(
        output.status.success() || output.status.code() == Some(1),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn add_dry_run_requires_args() {
    let bin = env!("CARGO_BIN_EXE_jcm");
    let output = Command::new(bin)
        .args(["add", "test", "https://example.com", "--dry-run"])
        .output()
        .expect("run add --dry-run");
    assert!(
        output.status.success() || output.status.code() == Some(3),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
