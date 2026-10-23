#![forbid(unsafe_code)]

//! Pure, synchronous WAF rule engine.

pub mod audit;
pub mod collections;
pub mod compile;
pub mod error;
pub mod eval;
pub mod model;
pub mod operators;
pub mod parser;
pub mod transforms;
pub mod variables;

pub use collections::{CollectionStore, MemoryCollectionStore, SharedCollectionStore};
pub use compile::{load_rules, LoadOptions};
pub use error::{EngineError, LoadError};
pub use eval::{evaluate, evaluate_phase, Decision, Evaluation, EvaluationState, RuleMatch};
pub use model::{CompiledRules, Phase};
pub use variables::request::{RequestContext, RequestView};
