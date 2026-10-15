// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Variable manipulation actions.
//!
//! These actions create, modify, or delete transaction variables during rule
//! evaluation. Variables are primarily used for scoring, tracking state, and
//! passing data between rules.

use crate::RuleVariable;
use crate::actions::ActionError;
use crate::operators::Macro;
use crate::transaction::{Transaction, VariableCollection};

/// `setvar` action - Creates, removes, or updates a variable.
///
/// Variable names are **case-insensitive** and automatically lowercased.
/// Currently only supports TX (transaction) variables.
///
/// # Syntax
///
/// - `TX.key` - Create variable and set to empty string
/// - `TX.key=value` - Set variable to value
/// - `TX.key=+5` - Add 5 to current value (arithmetic)
/// - `TX.key=-3` - Subtract 3 from current value (arithmetic)
/// - `!TX.key` - Remove variable
///
/// Both key and value support macro expansion using `%{VAR.key}` syntax.
///
/// # Arithmetic Operations
///
/// When the value starts with `+` or `-` followed by a number, it's treated
/// as an arithmetic operation. The current value is parsed as an integer,
/// the operation is applied, and the result is stored.
///
/// If the value after `+`/`-` is not a number, it's treated as a literal string.
/// For example, `TX.key=+++value` sets the key to the string "+++value".
///
/// # Arguments
///
/// Variable specification with optional value assignment
///
/// # Examples
///
/// ```text
/// # Create a variable and set its value to 1 (flag)
/// SecAction "id:100,setvar:TX.score"
///
/// # Initialize with a value
/// SecAction "id:101,setvar:TX.score=10"
///
/// # Remove a variable
/// SecAction "id:102,setvar:!TX.score"
///
/// # Arithmetic operations
/// SecAction "id:103,setvar:TX.score=+5"
/// SecAction "id:104,setvar:TX.score=-3"
///
/// # Using macros
/// SecRule ARGS:id "@gt 100" "id:105,setvar:TX.high_id=%{MATCHED_VAR}"
/// SecRule REQUEST_METHOD "POST" "id:106,setvar:TX.score=+%{TX.critical_score}"
/// ```
#[derive(Debug, Clone)]
pub struct SetvarAction {
    key: Macro,
    value: Macro,
    collection: RuleVariable,
    is_remove: bool,
}

impl SetvarAction {
    /// Parses `TX.key=value`, `TX.key` or `!TX.key`; key and value may contain macros.
    pub fn parse(data: &str) -> Result<Self, ActionError> {
        if data.is_empty() {
            return Err(ActionError::MissingArguments);
        }

        // Check for removal prefix
        let (is_remove, data) = match data.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, data),
        };

        // Split on '=' to get key and optional value
        let (key_part, value_part) = match data.split_once('=') {
            Some((key, value)) => (key, Some(value)),
            None => (data, None),
        };

        // Parse collection and key (e.g., "TX.score")
        let (col_name, key_name) = key_part.split_once('.').ok_or_else(|| {
            ActionError::InvalidArguments(
                "invalid arguments, expected syntax TX.{key}={value}".to_string(),
            )
        })?;

        // Validate collection is TX
        if col_name.to_uppercase() != "TX" {
            return Err(ActionError::InvalidArguments(
                "invalid arguments, expected collection TX".to_string(),
            ));
        }

        // Validate key is not empty
        if key_name.trim().is_empty() {
            return Err(ActionError::InvalidArguments(
                "invalid arguments, expected syntax TX.{key}={value}".to_string(),
            ));
        }

        Ok(Self {
            key: Macro::new(key_name)?,
            value: match value_part {
                Some(value) => Macro::new(value)?,
                None => Macro::empty(),
            },
            collection: col_name
                .parse::<RuleVariable>()
                .map_err(|e| ActionError::InvalidArguments(e.to_string()))?,
            is_remove,
        })
    }

    pub(crate) fn evaluate(&self, tx: &mut Transaction) {
        let key = self.key.expand(tx).to_lowercase();
        let value = self.value.expand(tx);

        // init() only accepts TX, which is always a map
        let Some(VariableCollection::Map(collection)) = tx.collection_mut(self.collection) else {
            return;
        };

        // Handle removal
        if self.is_remove {
            collection.remove(&key);
            return;
        }

        // Handle setting/updating
        if value.is_empty() {
            // No value specified - set to empty string
            collection.set(&key, vec![String::new()]);
            return;
        }

        // Check for arithmetic operations
        if value.starts_with('+') || value.starts_with('-') {
            let op = value.chars().next().unwrap();
            let operand_str = &value[1..];

            // Try to parse as number
            if let Ok(operand) = operand_str.parse::<i32>() {
                // Get current value
                let current_values = collection.get(&key);
                let current = if current_values.is_empty() {
                    0
                } else {
                    current_values[0].parse::<i32>().unwrap_or(0)
                };

                // Apply operation
                let result = if op == '+' {
                    current + operand
                } else {
                    current - operand
                };

                collection.set(&key, vec![result.to_string()]);
                return;
            }
            // If not a valid number, treat as literal string
            // Fall through to default case
        }

        // Default: set to literal value
        collection.set(&key, vec![value]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tx_value(tx: &Transaction, key: &str) -> Option<String> {
        tx.get_variable(RuleVariable::TX, Some(key))
    }

    // Init Tests
    #[test]
    fn test_setvar_no_arguments() {
        assert_eq!(
            SetvarAction::parse("").map(|_| ()),
            Err(ActionError::MissingArguments)
        );
    }

    #[test]
    fn test_setvar_non_tx_variable() {
        assert!(matches!(
            SetvarAction::parse("PATH_INFO=test").map(|_| ()),
            Err(ActionError::InvalidArguments(_))
        ));
    }

    #[test]
    fn test_setvar_tx_set_ok() {
        assert!(SetvarAction::parse("TX.some=test").map(|_| ()).is_ok());
    }

    #[test]
    fn test_setvar_tx_without_key_fails() {
        assert!(matches!(
            SetvarAction::parse("TX=test").map(|_| ()),
            Err(ActionError::InvalidArguments(_))
        ));
    }

    #[test]
    fn test_setvar_tx_with_empty_key_fails() {
        assert!(matches!(
            SetvarAction::parse("TX. =test").map(|_| ()),
            Err(ActionError::InvalidArguments(_))
        ));
    }

    // Evaluate Tests
    #[test]
    fn test_setvar_set_simple_value() {
        let action = SetvarAction::parse("TX.key=value").unwrap();

        let mut tx = Transaction::new("setvar-test");
        action.evaluate(&mut tx);

        assert_eq!(tx_value(&tx, "key"), Some("value".to_string()));
    }

    #[test]
    fn test_setvar_set_empty_value() {
        let action = SetvarAction::parse("TX.key").unwrap();

        let mut tx = Transaction::new("setvar-test");
        action.evaluate(&mut tx);

        assert_eq!(tx_value(&tx, "key"), Some("".to_string()));
    }

    #[test]
    fn test_setvar_arithmetic_add() {
        let mut tx = Transaction::new("setvar-test");

        // Set initial value
        let action1 = SetvarAction::parse("TX.score=5").unwrap();
        action1.evaluate(&mut tx);

        // Add 3
        let action2 = SetvarAction::parse("TX.score=+3").unwrap();
        action2.evaluate(&mut tx);

        assert_eq!(tx_value(&tx, "score"), Some("8".to_string()));
    }

    #[test]
    fn test_setvar_arithmetic_subtract() {
        let mut tx = Transaction::new("setvar-test");

        // Set initial value
        let action1 = SetvarAction::parse("TX.score=10").unwrap();
        action1.evaluate(&mut tx);

        // Subtract 3
        let action2 = SetvarAction::parse("TX.score=-3").unwrap();
        action2.evaluate(&mut tx);

        assert_eq!(tx_value(&tx, "score"), Some("7".to_string()));
    }

    #[test]
    fn test_setvar_arithmetic_add_to_zero() {
        let mut tx = Transaction::new("setvar-test");

        // Add to non-existent variable (should start at 0)
        let action = SetvarAction::parse("TX.score=+5").unwrap();
        action.evaluate(&mut tx);

        assert_eq!(tx_value(&tx, "score"), Some("5".to_string()));
    }

    #[test]
    fn test_setvar_arithmetic_negative_result() {
        let mut tx = Transaction::new("setvar-test");

        // Set to -5
        let action1 = SetvarAction::parse("TX.score=-5").unwrap();
        action1.evaluate(&mut tx);

        // Add 5 (should be 0)
        let action2 = SetvarAction::parse("TX.score=+5").unwrap();
        action2.evaluate(&mut tx);

        assert_eq!(tx_value(&tx, "score"), Some("0".to_string()));
    }

    #[test]
    fn test_setvar_non_numeric_plus_literal() {
        let action = SetvarAction::parse("TX.key=+++expected_value").unwrap();

        let mut tx = Transaction::new("setvar-test");
        action.evaluate(&mut tx);

        // Non-numeric value after + should be treated as literal
        assert_eq!(tx_value(&tx, "key"), Some("+++expected_value".to_string()));
    }

    #[test]
    fn test_setvar_non_numeric_minus_literal() {
        let action = SetvarAction::parse("TX.key=----expected_value").unwrap();

        let mut tx = Transaction::new("setvar-test");
        action.evaluate(&mut tx);

        // Non-numeric value after - should be treated as literal
        assert_eq!(tx_value(&tx, "key"), Some("----expected_value".to_string()));
    }

    #[test]
    fn test_setvar_remove() {
        let mut tx = Transaction::new("setvar-test");

        // Set value
        let action1 = SetvarAction::parse("TX.key=value").unwrap();
        action1.evaluate(&mut tx);
        assert_eq!(tx_value(&tx, "key"), Some("value".to_string()));

        // Remove it
        let action2 = SetvarAction::parse("!TX.key").unwrap();
        action2.evaluate(&mut tx);
        assert_eq!(tx_value(&tx, "key"), None);
    }

    #[test]
    fn test_setvar_case_insensitive_key() {
        let action = SetvarAction::parse("TX.MyKey=value").unwrap();

        let mut tx = Transaction::new("setvar-test");
        action.evaluate(&mut tx);

        // Keys are lowercased
        assert_eq!(tx_value(&tx, "mykey"), Some("value".to_string()));
        assert_eq!(tx_value(&tx, "MyKey"), Some("value".to_string()));
    }
}
