use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum, builder::BoolishValueParser};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Parser)]
#[command(name = "jcm", about = "Java Cacerts Manager", version)]
pub struct Cli {
    #[command(flatten)]
    pub global: GlobalOpts,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Clone, Debug, clap::Args)]
pub struct GlobalOpts {
    /// Quiet output (errors only)
    #[arg(
        short,
        long,
        global = true,
        env = "JCM_QUIET",
        value_parser = BoolishValueParser::new(),
        default_value_t = false
    )]
    pub quiet: bool,

    /// Verbose output
    #[arg(
        short,
        long,
        global = true,
        env = "JCM_VERBOSE",
        value_parser = BoolishValueParser::new(),
        default_value_t = false
    )]
    pub verbose: bool,

    #[arg(long, global = true, env = "JAVA_HOME")]
    pub java_home: Option<PathBuf>,

    #[arg(long, global = true, env = "JCM_CACERTS")]
    pub cacerts: Option<PathBuf>,

    #[arg(long, global = true, env = "JCM_STORE_PASS")]
    pub store_pass: Option<String>,

    #[arg(
        long,
        value_enum,
        default_value_t = ChainTarget::Root,
        global = true,
        env = "JCM_CHAIN"
    )]
    pub chain: ChainTarget,

    #[arg(long, default_value = "jcm-", global = true, env = "JCM_ALIAS_PREFIX")]
    pub alias_prefix: String,

    #[arg(
        long,
        value_enum,
        default_value_t = ElevateMode::Auto,
        global = true,
        env = "JCM_ELEVATE"
    )]
    pub elevate: ElevateMode,
}

#[derive(Clone, Debug, Subcommand)]
pub enum Commands {
    /// Fetch a URL's TLS chain and import into cacerts as jcm-<alias>
    Add {
        #[arg(value_name = "ALIAS", env = "JCM_ALIAS")]
        alias: String,
        #[arg(value_name = "URL", env = "JCM_URL")]
        url: String,
        /// Show planned import without modifying cacerts
        #[arg(
            long,
            env = "JCM_DRY_RUN",
            value_parser = BoolishValueParser::new(),
            default_value_t = false
        )]
        dry_run: bool,
    },
    /// Remove jcm-<alias> from cacerts
    Remove {
        #[arg(value_name = "ALIAS", env = "JCM_ALIAS")]
        alias: String,
        /// Show planned removal without modifying cacerts
        #[arg(
            long,
            env = "JCM_DRY_RUN",
            value_parser = BoolishValueParser::new(),
            default_value_t = false
        )]
        dry_run: bool,
    },
    /// List entries in cacerts (jcm-* by default)
    List {
        /// List every keystore entry, not only jcm-*
        #[arg(
            long,
            env = "JCM_LIST_ALL",
            value_parser = BoolishValueParser::new(),
            default_value_t = false
        )]
        all: bool,
    },
    /// Show certificate details for a jcm-* alias in cacerts
    Show {
        #[arg(value_name = "ALIAS", env = "JCM_ALIAS")]
        alias: String,
    },
    /// Inspect TLS certificates for a URL (read-only, no keystore changes)
    Inspect {
        #[arg(value_name = "URL", env = "JCM_URL")]
        url: String,
        /// Print the full chain as an indented tree
        #[arg(
            long,
            env = "JCM_GRAPH",
            value_parser = BoolishValueParser::new(),
            default_value_t = false
        )]
        graph: bool,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum, Serialize, Deserialize, PartialEq, Eq)]
pub enum ElevateMode {
    Auto,
    Always,
    Never,
}

impl Default for ElevateMode {
    fn default() -> Self {
        Self::Auto
    }
}

#[derive(Clone, Copy, Debug, Default, ValueEnum, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChainTarget {
    #[default]
    Root,
    Leaf,
    Intermediate,
    Full,
    #[value(name = "0")]
    Index0,
    #[value(name = "1")]
    Index1,
    #[value(name = "2")]
    Index2,
    #[value(name = "3")]
    Index3,
    #[value(name = "4")]
    Index4,
}

impl ChainTarget {
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "root" => Some(Self::Root),
            "leaf" => Some(Self::Leaf),
            "intermediate" => Some(Self::Intermediate),
            "full" => Some(Self::Full),
            "0" => Some(Self::Index0),
            "1" => Some(Self::Index1),
            "2" => Some(Self::Index2),
            "3" => Some(Self::Index3),
            "4" => Some(Self::Index4),
            _ => s.parse::<usize>().ok().map(|n| Self::from_index(n)),
        }
    }

    pub fn from_index(n: usize) -> Self {
        match n {
            0 => Self::Index0,
            1 => Self::Index1,
            2 => Self::Index2,
            3 => Self::Index3,
            4 => Self::Index4,
            _ => Self::Index4,
        }
    }

    pub fn index(self) -> Option<usize> {
        match self {
            Self::Index0 => Some(0),
            Self::Index1 => Some(1),
            Self::Index2 => Some(2),
            Self::Index3 => Some(3),
            Self::Index4 => Some(4),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::Leaf => "leaf",
            Self::Intermediate => "intermediate",
            Self::Full => "full",
            Self::Index0 => "0",
            Self::Index1 => "1",
            Self::Index2 => "2",
            Self::Index3 => "3",
            Self::Index4 => "4",
        }
    }
}
