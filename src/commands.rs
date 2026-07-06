use anyhow::{Context, Result, bail};
use clap::CommandFactory;

use crate::cert::{fetch_chain, format_chain_graph, select_certs};
use crate::cli::{Cli, Commands, GlobalOpts};
use crate::elevation::cacerts_writable;
use crate::exit;
use crate::jvm::{self, resolve_jvm};
use crate::keystore::{list_entries, show_alias};
use crate::logging::{self, LogMode};
use crate::ops::{
    format_add_plan, format_remove_plan, plan_would_mutate_add, plan_would_mutate_remove, run_add,
    run_remove,
};
use crate::paths::{resolve_keystore_alias, validate_alias};

pub struct RunContext {
    pub opts: GlobalOpts,
    pub log: LogMode,
    pub jvm: jvm::JvmInfo,
}

impl RunContext {
    pub fn build(cli: &Cli) -> Result<Self> {
        let log = if cli.global.quiet {
            LogMode::Quiet
        } else if cli.global.verbose {
            LogMode::Verbose
        } else {
            LogMode::Normal
        };
        logging::init(log);
        let jvm = resolve_jvm(&cli.global)?;
        Ok(Self {
            opts: cli.global.clone(),
            log,
            jvm,
        })
    }
}

pub fn run(cli: Cli) -> Result<i32> {
    match &cli.command {
        None => {
            Cli::command().print_help()?;
            println!();
            Ok(exit::SUCCESS)
        }
        Some(Commands::Inspect { url, graph }) => cmd_inspect(&cli.global, url, *graph),
        Some(Commands::Add { alias, url, dry_run }) => {
            let ctx = RunContext::build(&cli)?;
            cmd_add(&ctx, alias, url, *dry_run)
        }
        Some(Commands::Remove { alias, dry_run }) => {
            let ctx = RunContext::build(&cli)?;
            cmd_remove(&ctx, alias, *dry_run)
        }
        Some(Commands::List { all }) => {
            let ctx = RunContext::build(&cli)?;
            cmd_list(&ctx, *all)
        }
        Some(Commands::Show { alias }) => {
            let ctx = RunContext::build(&cli)?;
            cmd_show(&ctx, alias)
        }
    }
}

fn cmd_add(ctx: &RunContext, alias: &str, url: &str, dry_run: bool) -> Result<i32> {
    let plan = run_add(
        &ctx.jvm,
        &ctx.opts,
        alias,
        url,
        ctx.opts.chain,
        dry_run,
        ctx.log,
    )?;
    println!("{}", format_add_plan(&plan, dry_run));
    if dry_run && plan_would_mutate_add(&plan) {
        return Ok(exit::PENDING_CHANGES);
    }
    Ok(exit::SUCCESS)
}

fn cmd_remove(ctx: &RunContext, alias: &str, dry_run: bool) -> Result<i32> {
    let plan = run_remove(&ctx.jvm, &ctx.opts, alias, dry_run, ctx.log)?;
    println!("{}", format_remove_plan(&plan, dry_run));
    if dry_run && plan_would_mutate_remove(&plan) {
        return Ok(exit::PENDING_CHANGES);
    }
    Ok(exit::SUCCESS)
}

fn cmd_list(ctx: &RunContext, all: bool) -> Result<i32> {
    let store = list_entries(&ctx.jvm, &ctx.opts.alias_prefix, ctx.log)
        .with_context(|| diagnose_keystore_access(&ctx.jvm))?;
    let entries: Vec<_> = if all {
        store
    } else {
        store.into_iter().filter(|e| e.managed).collect()
    };
    if entries.is_empty() {
        if !all {
            println!("(no jcm-* entries in cacerts)");
        }
        return Ok(exit::SUCCESS);
    }
    for entry in entries {
        match &entry.fingerprint_sha256 {
            Some(fp) => println!("{}\t{fp}", entry.alias),
            None => println!("{}", entry.alias),
        }
    }
    Ok(exit::SUCCESS)
}

fn cmd_show(ctx: &RunContext, alias: &str) -> Result<i32> {
    validate_alias(alias)?;
    let ks_alias = resolve_keystore_alias(alias, &ctx.opts.alias_prefix);
    let detail = show_alias(&ctx.jvm, &ks_alias, ctx.log)
        .with_context(|| diagnose_keystore_access(&ctx.jvm))?;
    if detail.is_empty() {
        bail!("alias not found in cacerts: {ks_alias}");
    }
    println!("alias: {ks_alias}");
    println!("{detail}");
    Ok(exit::SUCCESS)
}

fn cmd_inspect(opts: &GlobalOpts, url: &str, graph: bool) -> Result<i32> {
    let log = if opts.quiet {
        LogMode::Quiet
    } else if opts.verbose {
        LogMode::Verbose
    } else {
        LogMode::Normal
    };
    logging::init(log);

    let certs = fetch_chain(url, 20)?;
    if graph {
        let selected = select_certs(&certs, opts.chain, "inspect", "jcm-")?;
        let highlight: std::collections::HashSet<usize> =
            selected.iter().map(|s| s.cert.index).collect();
        print!("{}", format_chain_graph(url, &certs, Some(&highlight)));
        return Ok(exit::SUCCESS);
    }
    let selected = select_certs(&certs, opts.chain, "inspect", "jcm-")?;
    println!("url: {url}");
    println!("chain: {} certificates", certs.len());
    for sel in selected {
        let c = &sel.cert;
        println!("selected (chain={}):", opts.chain.as_str());
        println!("  position: {}", c.index);
        println!("  subject: {}", c.subject);
        println!("  issuer: {}", c.issuer);
        println!("  valid: {} .. {}", c.not_before, c.not_after);
        println!("  sha256: {}", c.fingerprint_sha256);
        println!("  self_signed: {}", c.is_self_signed);
    }
    Ok(exit::SUCCESS)
}

fn diagnose_keystore_access(jvm: &jvm::JvmInfo) -> String {
    let mut lines = vec![format!("cacerts: {}", jvm.cacerts.display())];
    if !jvm.cacerts.exists() {
        lines.push("hint: cacerts file does not exist; set --cacerts or --java-home".to_string());
    } else if !cacerts_writable(&jvm.cacerts) {
        lines.push(
            "hint: cacerts is read-only for writes; use --elevate auto on add/remove".to_string(),
        );
    }
    if !jvm.keytool_bin.exists() {
        lines.push("hint: keytool not found; set --java-home or JAVA_HOME".to_string());
    }
    lines.join("\n")
}
