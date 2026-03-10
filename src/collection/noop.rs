// Copyright 2024 Coraza Rust Contributors
// SPDX-License-Identifier: Apache-2.0

//! No-op collection implementation.

use super::{Collection, MatchData};

/// A no-op collection that always returns empty results.
///
/// Used as a placeholder when a collection is not available.
pub struct Noop;

impl Collection for Noop {
    fn find_all(&self) -> Vec<MatchData> {
        Vec::new()
    }

    fn name(&self) -> &str {
        ""
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_noop() {
        let noop = Noop;
        assert_eq!(noop.find_all().len(), 0);
        assert_eq!(noop.name(), "");
    }
}
