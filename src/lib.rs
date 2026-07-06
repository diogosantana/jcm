pub mod cert;
pub mod cli;
pub mod commands;
pub mod config;
pub mod elevation;
pub mod jvm;
pub mod keystore;
pub mod logging;
pub mod ops;
pub mod paths;
pub mod platform;
pub mod temp;

pub use cli::{ChainTarget, ElevateMode, GlobalOpts};

pub const DEFAULT_ALIAS_PREFIX: &str = "jcm-";
pub const DEFAULT_STORE_PASS: &str = "changeit";

pub mod exit {
    pub const SUCCESS: i32 = 0;
    pub const OPERATIONAL: i32 = 1;
    pub const VALIDATION: i32 = 2;
    pub const PENDING_CHANGES: i32 = 3;
}
