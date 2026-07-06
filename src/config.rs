use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::ValueEnum;
use serde::Deserialize;
use tracing::warn;

use crate::cli::ChainTarget;
use crate::logging::LogMode;

#[derive(Clone, Copy, Debug, Default, ValueEnum, PartialEq, Eq)]
pub enum ConfigFormat {
    #[default]
    Auto,
    Txt,
    Json,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustEntry {
    pub alias: String,
    pub url: String,
    pub chain: ChainTarget,
    pub source: PathBuf,
}

pub fn load_merged_configs(
    files: &[PathBuf],
    format: ConfigFormat,
    default_chain: ChainTarget,
    strict: bool,
    log: LogMode,
) -> Result<Vec<TrustEntry>> {
    let mut merged: HashMap<String, TrustEntry> = HashMap::new();
    for file in files {
        let entries = load_config_file(file, format, default_chain, log)?;
        for entry in entries {
            if let Some(prev) = merged.get(&entry.alias) {
                if strict {
                    bail!(
                        "duplicate alias '{}' between {} and {}",
                        entry.alias,
                        prev.source.display(),
                        entry.source.display()
                    );
                }
                if crate::logging::info_enabled(log) {
                    warn!(
                        "duplicate alias '{}' — using definition from {}",
                        entry.alias,
                        entry.source.display()
                    );
                }
            }
            merged.insert(entry.alias.clone(), entry);
        }
    }
    let mut out: Vec<_> = merged.into_values().collect();
    out.sort_by(|a, b| a.alias.cmp(&b.alias));
    Ok(out)
}

pub fn load_config_file(
    path: &Path,
    format: ConfigFormat,
    default_chain: ChainTarget,
    log: LogMode,
) -> Result<Vec<TrustEntry>> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("read config {}", path.display()))?;
    let fmt = match format {
        ConfigFormat::Auto => {
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                ConfigFormat::Json
            } else {
                ConfigFormat::Txt
            }
        }
        other => other,
    };
    match fmt {
        ConfigFormat::Txt => parse_txt(&content, path, default_chain),
        ConfigFormat::Json => parse_json(&content, path, default_chain, log),
        ConfigFormat::Auto => unreachable!(),
    }
}

fn parse_txt(content: &str, source: &Path, default_chain: ChainTarget) -> Result<Vec<TrustEntry>> {
    let mut entries = Vec::new();
    for (lineno, line) in content.lines().enumerate() {
        let line = line.trim_end_matches('\r').trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            bail!("{}:{}: expected '<alias> <url> [chain]'", source.display(), lineno + 1);
        }
        let alias = parts[0].to_string();
        let url = parts[1].to_string();
        validate_url(&url)?;
        let chain = parts
            .get(2)
            .and_then(|s| ChainTarget::from_str_loose(s))
            .unwrap_or(default_chain);
        entries.push(TrustEntry {
            alias,
            url,
            chain,
            source: source.to_path_buf(),
        });
    }
    Ok(entries)
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum JsonRoot {
    Wrapped { entries: Vec<JsonEntry> },
    List(Vec<JsonEntry>),
    Map(HashMap<String, String>),
}

#[derive(Debug, Deserialize)]
struct JsonEntry {
    alias: String,
    url: String,
    #[serde(default)]
    chain: Option<JsonChain>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum JsonChain {
    Named(String),
    Index(usize),
}

fn parse_json(
    content: &str,
    source: &Path,
    default_chain: ChainTarget,
    log: LogMode,
) -> Result<Vec<TrustEntry>> {
    let root: JsonRoot = serde_json::from_str(content)
        .with_context(|| format!("parse json config {}", source.display()))?;
    let mut entries = Vec::new();
    match root {
        JsonRoot::Wrapped { entries: list } | JsonRoot::List(list) => {
            for item in list {
                let chain = item
                    .chain
                    .map(json_chain_to_target)
                    .unwrap_or(default_chain);
                validate_url(&item.url)?;
                entries.push(TrustEntry {
                    alias: item.alias,
                    url: item.url,
                    chain,
                    source: source.to_path_buf(),
                });
            }
        }
        JsonRoot::Map(map) => {
            if crate::logging::debug_enabled(log) {
                warn!("compact json map does not support per-entry chain in {}", source.display());
            }
            for (alias, url) in map {
                validate_url(&url)?;
                entries.push(TrustEntry {
                    alias,
                    url,
                    chain: default_chain,
                    source: source.to_path_buf(),
                });
            }
        }
    }
    Ok(entries)
}

fn json_chain_to_target(chain: JsonChain) -> ChainTarget {
    match chain {
        JsonChain::Index(n) => ChainTarget::from_index(n),
        JsonChain::Named(s) => ChainTarget::from_str_loose(&s).unwrap_or(ChainTarget::Root),
    }
}

fn validate_url(url: &str) -> Result<()> {
    let parsed = url::Url::parse(url).with_context(|| format!("invalid url: {url}"))?;
    if parsed.scheme() != "https" && parsed.scheme() != "http" {
        bail!("url must use http or https: {url}");
    }
    if parsed.host().is_none() {
        bail!("url must include host: {url}");
    }
    Ok(())
}
