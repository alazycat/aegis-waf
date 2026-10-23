#![forbid(unsafe_code)]

//! Pure, synchronous WAF rule engine.

pub mod compile;
pub mod error;
pub mod model;
pub mod operators;
pub mod parser;
pub mod transforms;

pub use compile::{load_rules, LoadOptions};
pub use error::{EngineError, LoadError};
pub use model::CompiledRules;
