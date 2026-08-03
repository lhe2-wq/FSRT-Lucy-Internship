//! Forge pen-testing toolkit.

mod mint_common;
mod mint_fct;

pub use mint_common::{MintError, Result};

pub use mint_fct::run_mint_fct;
