use std::collections::HashSet;

use anyhow::{Result, bail};
use tracing::{info, warn};

use crate::cert::{fetch_chain, select_certs};
use crate::cli::{ChainTarget, GlobalOpts};
use crate::elevation::prepare_mutation;
use crate::jvm::JvmInfo;
use crate::keystore::{
    alias_set, delete_alias, import_cert, list_entries, verify_builtin_aliases_unchanged,
};
use crate::logging::LogMode;
use crate::paths::{resolve_keystore_alias, validate_alias};
use crate::temp::TempWorkspace;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MutationKind {
    Add,
    Update,
    Skip,
}

#[derive(Clone, Debug)]
pub struct PlannedCert {
    pub keystore_alias: String,
    pub subject: String,
    pub fingerprint_sha256: String,
}

#[derive(Clone, Debug)]
pub struct AddPlan {
    pub kind: MutationKind,
    pub alias: String,
    pub url: String,
    pub chain: ChainTarget,
    pub certs: Vec<PlannedCert>,
}

#[derive(Clone, Debug)]
pub struct RemovePlan {
    pub alias: String,
    pub keystore_aliases: Vec<String>,
}

pub fn plan_add(
    jvm: &JvmInfo,
    opts: &GlobalOpts,
    alias: &str,
    url: &str,
    chain: ChainTarget,
    log: LogMode,
) -> Result<AddPlan> {
    validate_alias(alias)?;
    let store = list_entries(jvm, &opts.alias_prefix, log)?;
    let store_aliases = alias_set(&store);
    let selected = select_certs(&fetch_chain(url, 20)?, chain, alias, &opts.alias_prefix)?;
    let certs: Vec<PlannedCert> = selected
        .iter()
        .map(|sel| PlannedCert {
            keystore_alias: sel.keystore_alias.clone(),
            subject: sel.cert.subject.clone(),
            fingerprint_sha256: sel.cert.fingerprint_sha256.clone(),
        })
        .collect();
    let expected: Vec<String> = certs.iter().map(|c| c.keystore_alias.clone()).collect();

    let kind = if expected.iter().all(|a| store_aliases.contains(a)) {
        MutationKind::Skip
    } else if resolve_remove_aliases(opts, alias, jvm, log)?.is_empty() {
        MutationKind::Add
    } else {
        MutationKind::Update
    };

    Ok(AddPlan {
        kind,
        alias: alias.to_string(),
        url: url.to_string(),
        chain,
        certs,
    })
}

pub fn run_add(
    jvm: &JvmInfo,
    opts: &GlobalOpts,
    alias: &str,
    url: &str,
    chain: ChainTarget,
    dry_run: bool,
    log: LogMode,
) -> Result<AddPlan> {
    let plan = plan_add(jvm, opts, alias, url, chain, log)?;

    if dry_run || plan.kind == MutationKind::Skip {
        return Ok(plan);
    }

    if matches!(chain, ChainTarget::Leaf) && crate::logging::info_enabled(log) {
        warn!(
            "importing leaf certificate for {} — unusual for truststores",
            plan.alias
        );
    }

    let elevation = prepare_mutation(&jvm.cacerts, opts.elevate, log)?;
    let before = list_entries(jvm, &opts.alias_prefix, log)?;

    for ks_alias in resolve_remove_aliases(opts, alias, jvm, log)? {
        delete_alias(jvm, &ks_alias, elevation, log)?;
    }

    let selected = select_certs(&fetch_chain(url, 20)?, chain, alias, &opts.alias_prefix)?;
    let temp = TempWorkspace::new()?;
    for sel in selected {
        let pem_file = temp.write_pem(&sel.keystore_alias, &sel.cert.pem)?;
        import_cert(jvm, &sel.keystore_alias, &pem_file, elevation, log)?;
    }

    let after = list_entries(jvm, &opts.alias_prefix, log)?;
    verify_builtin_aliases_unchanged(&before, &after, &opts.alias_prefix)?;

    if crate::logging::info_enabled(log) {
        info!("added {}", alias);
    }
    Ok(plan)
}

pub fn plan_remove(
    jvm: &JvmInfo,
    opts: &GlobalOpts,
    alias: &str,
    log: LogMode,
) -> Result<RemovePlan> {
    validate_alias(alias)?;
    let ks_aliases = resolve_remove_aliases(opts, alias, jvm, log)?;
    if ks_aliases.is_empty() {
        bail!(
            "alias not found in cacerts: {} (looked for {})",
            alias,
            resolve_keystore_alias(alias, &opts.alias_prefix)
        );
    }
    Ok(RemovePlan {
        alias: alias.to_string(),
        keystore_aliases: ks_aliases,
    })
}

pub fn run_remove(
    jvm: &JvmInfo,
    opts: &GlobalOpts,
    alias: &str,
    dry_run: bool,
    log: LogMode,
) -> Result<RemovePlan> {
    let plan = plan_remove(jvm, opts, alias, log)?;

    if dry_run {
        return Ok(plan);
    }

    let elevation = prepare_mutation(&jvm.cacerts, opts.elevate, log)?;
    let before = list_entries(jvm, &opts.alias_prefix, log)?;
    for ks_alias in &plan.keystore_aliases {
        delete_alias(jvm, ks_alias, elevation, log)?;
    }
    let after = list_entries(jvm, &opts.alias_prefix, log)?;
    verify_builtin_aliases_unchanged(&before, &after, &opts.alias_prefix)?;

    if crate::logging::info_enabled(log) {
        info!("removed {}", alias);
    }
    Ok(plan)
}

fn resolve_remove_aliases(
    opts: &GlobalOpts,
    alias: &str,
    jvm: &JvmInfo,
    log: LogMode,
) -> Result<Vec<String>> {
    let store = list_entries(jvm, &opts.alias_prefix, log)?;
    let store_aliases: HashSet<_> = alias_set(&store);
    let primary = resolve_keystore_alias(alias, &opts.alias_prefix);
    if store_aliases.contains(&primary) {
        return Ok(vec![primary]);
    }

    let prefix = format!("{}{}-", opts.alias_prefix, alias);
    let mut matches: Vec<String> = store
        .iter()
        .filter(|e| e.alias.starts_with(&prefix))
        .map(|e| e.alias.clone())
        .collect();
    matches.sort();
    Ok(matches)
}

pub fn format_add_plan(plan: &AddPlan, dry_run: bool) -> String {
    let verb = if dry_run { "would" } else { "did" };
    let action = match plan.kind {
        MutationKind::Add => "add",
        MutationKind::Update => "update",
        MutationKind::Skip => "skip",
    };
    let mut out = format!(
        "{verb} {action} {} from {} (chain={})",
        plan.alias,
        plan.url,
        plan.chain.as_str()
    );
    for cert in &plan.certs {
        out.push_str(&format!(
            "\n  {} | {} | {}",
            cert.keystore_alias, cert.subject, cert.fingerprint_sha256
        ));
    }
    out
}

pub fn format_remove_plan(plan: &RemovePlan, dry_run: bool) -> String {
    let verb = if dry_run { "would remove" } else { "removed" };
    let mut out = format!("{verb} {}", plan.alias);
    for ks in &plan.keystore_aliases {
        out.push_str(&format!("\n  {ks}"));
    }
    out
}

pub fn plan_would_mutate_add(plan: &AddPlan) -> bool {
    !matches!(plan.kind, MutationKind::Skip)
}

pub fn plan_would_mutate_remove(_plan: &RemovePlan) -> bool {
    true
}
