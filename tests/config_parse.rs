use std::path::PathBuf;

use jcm::cli::ChainTarget;
use jcm::config::{load_config_file, ConfigFormat};
use jcm::logging::LogMode;

#[test]
fn parse_txt_with_chain() {
    let dir = tempfile_dir();
    let file = dir.join("trust.txt");
    std::fs::write(
        &file,
        "api https://example.com leaf\n# comment\nroot-ca https://example.org\n",
    )
    .unwrap();
    let entries = load_config_file(&file, ConfigFormat::Txt, ChainTarget::Root, LogMode::Quiet).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].alias, "api");
    assert_eq!(entries[0].chain, ChainTarget::Leaf);
}

#[test]
fn parse_json_entries() {
    let dir = tempfile_dir();
    let file = dir.join("trust.json");
    std::fs::write(
        &file,
        r#"{"entries":[{"alias":"a","url":"https://example.com","chain":"root"}]}"#,
    )
    .unwrap();
    let entries = load_config_file(&file, ConfigFormat::Json, ChainTarget::Root, LogMode::Quiet).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].alias, "a");
}

fn tempfile_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("jcm-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}
