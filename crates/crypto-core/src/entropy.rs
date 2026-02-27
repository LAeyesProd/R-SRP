//! Entropy health checks for runtime fail-closed controls.

use crate::{CryptoError, Result};

const ENTROPY_SAMPLE_SIZE: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntropyHealthReport {
    pub source: &'static str,
    pub sample_size: usize,
}

/// Perform a lightweight runtime entropy self-test using OS randomness.
///
/// The check intentionally avoids blocking diagnostics and only verifies that:
/// - OS RNG is reachable,
/// - samples are not trivially degenerate.
pub fn entropy_health_check() -> Result<EntropyHealthReport> {
    let mut sample_a = [0u8; ENTROPY_SAMPLE_SIZE];
    let mut sample_b = [0u8; ENTROPY_SAMPLE_SIZE];

    getrandom::getrandom(&mut sample_a)
        .map_err(|e| CryptoError::KeyError(format!("OS entropy unavailable: {e}")))?;
    getrandom::getrandom(&mut sample_b)
        .map_err(|e| CryptoError::KeyError(format!("OS entropy unavailable: {e}")))?;

    if sample_a.iter().all(|b| *b == 0) && sample_b.iter().all(|b| *b == 0) {
        return Err(CryptoError::KeyError(
            "Entropy self-test failed: degenerate all-zero samples".to_string(),
        ));
    }

    if sample_a == sample_b {
        return Err(CryptoError::KeyError(
            "Entropy self-test failed: identical consecutive RNG samples".to_string(),
        ));
    }

    Ok(EntropyHealthReport {
        source: "os_rng",
        sample_size: ENTROPY_SAMPLE_SIZE,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_health_check_reports_ok() {
        let report = entropy_health_check().expect("os entropy health check");
        assert_eq!(report.source, "os_rng");
        assert_eq!(report.sample_size, ENTROPY_SAMPLE_SIZE);
    }
}
