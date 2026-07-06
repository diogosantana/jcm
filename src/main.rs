use std::process::ExitCode;

use anyhow::Result;
use clap::Parser;

use jcm::cli::Cli;
use jcm::commands;

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code as u8),
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::from(jcm::exit::OPERATIONAL as u8)
        }
    }
}

fn run() -> Result<i32> {
    let cli = Cli::parse();
    commands::run(cli)
}
