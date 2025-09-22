//! Benteng PQC SDK Core Library

pub mod crypto;
pub mod envelope;
pub mod error;
pub mod policy;

// Re-exports
pub use envelope::{AadExtensions, AlgorithmSet, Envelope};
pub use error::{BentengError, Result};
pub use policy::Policy;

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert_eq!(VERSION, "0.1.0");
    }
}
