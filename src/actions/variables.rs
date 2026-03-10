// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Variable manipulation actions.
//!
//! These actions create, modify, or delete transaction variables during rule
//! evaluation. Variables are primarily used for scoring, tracking state, and
//! passing data between rules.

use crate::RuleVariable;
use crate::actions::{Action, ActionError, ActionType, RuleMetadata, TransactionState};
use crate::operators::Macro;

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
#[derive(Debug)]
pub struct SetvarAction {
    key: Macro,
    value: Macro,
    collection: RuleVariable,
    is_remove: bool,
}

impl SetvarAction {
    pub fn new() -> Self {
        Self {
            key: Macro::empty(),
            value: Macro::empty(),
            collection: RuleVariable::TX,
            is_remove: false,
        }
    }
}

impl Default for SetvarAction {
    fn default() -> Self {
        Self::new()
    }
}

impl Action for SetvarAction {
    fn init(&mut self, _rule: &mut dyn RuleMetadata, data: &str) -> Result<(), ActionError> {
        if data.is_empty() {
            return Err(ActionError::MissingArguments);
        }

        let mut data = data;

        // Check for removal prefix
        if data.starts_with('!') {
            self.is_remove = true;
            data = &data[1..];
        }

        // Split on '=' to get key and optional value
        let (key_part, value_part) = if let Some(pos) = data.find('=') {
            (&data[..pos], Some(&data[pos + 1..]))
        } else {
            (data, None)
        };

        // Parse collection and key (e.g., "TX.score")
        let (col_name, key_name) = if let Some(pos) = key_part.find('.') {
            (&key_part[..pos], &key_part[pos + 1..])
        } else {
            return Err(ActionError::InvalidArguments(
                "invalid arguments, expected syntax TX.{key}={value}".to_string(),
            ));
        };

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

        // Parse collection
        self.collection = col_name
            .parse::<RuleVariable>()
            .map_err(|e| ActionError::InvalidArguments(e.to_string()))?;

        // Parse key with macro expansion support
        self.key = Macro::new(key_name)?;

        // Parse value if present
        if let Some(val) = value_part {
            self.value = Macro::new(val)?;
        }

        Ok(())
    }

    fn evaluate(&self, _rule: &dyn RuleMetadata, tx: &mut dyn TransactionState) {
        let key = self.key.expand(Some(tx)).to_lowercase();
        let value = self.value.expand(Some(tx));

        // Get the TX collection
        let collection = match tx.collection_mut(self.collection) {
            Some(col) => col,
            None => {
                // Collection not available - this shouldn't happen for TX
                return;
            }
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

    fn action_type(&self) -> ActionType {
        ActionType::Nondisruptive
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RuleSeverity;
    use crate::collection::{Keyed, Map, MapCollection};
    use crate::operators::Macro;

    // Mock RuleMetadata for testing
    struct MockRule;

    impl RuleMetadata for MockRule {
        fn id(&self) -> i32 {
            0
        }
        fn parent_id(&self) -> i32 {
            0
        }
        fn status(&self) -> i32 {
            0
        }
        fn set_id(&mut self, _id: i32) {}
        fn set_msg(&mut self, _msg: Macro) {}
        fn set_severity(&mut self, _severity: RuleSeverity) {}
        fn set_has_chain(&mut self, _has_chain: bool) {}
        fn set_rev(&mut self, _rev: String) {}
        fn set_ver(&mut self, _ver: String) {}
        fn set_maturity(&mut self, _maturity: u8) {}
        fn add_tag(&mut self, _tag: String) {}
        fn set_log_data(&mut self, _log_data: Macro) {}
        fn set_status(&mut self, _status: i32) {}
        fn set_log(&mut self, _enabled: bool) {}
        fn set_audit_log(&mut self, _enabled: bool) {}
    }

    // Mock TransactionState for testing
    struct MockTransaction {
        tx_vars: Map,
    }

    impl MockTransaction {
        fn new() -> Self {
            Self {
                tx_vars: Map::new_case_sensitive(RuleVariable::TX),
            }
        }

        fn get_tx_value(&self, key: &str) -> Option<String> {
            let values = self.tx_vars.get(&key.to_lowercase());
            if values.is_empty() {
                None
            } else {
                Some(values[0].clone())
            }
        }
    }

    impl TransactionState for MockTransaction {
        fn get_variable(&self, variable: RuleVariable, key: Option<&str>) -> Option<String> {
            if variable == RuleVariable::TX {
                if let Some(k) = key {
                    self.get_tx_value(&k.to_lowercase())
                } else {
                    None
                }
            } else {
                None
            }
        }

        fn collection_mut(&mut self, variable: RuleVariable) -> Option<&mut dyn MapCollection> {
            if variable == RuleVariable::TX {
                Some(&mut self.tx_vars)
            } else {
                None
            }
        }

        fn interrupt(&mut self, _rule_id: i32, _action: &str, _status: i32, _data: &str) {}
        fn set_allow_type(&mut self, _allow_type: crate::actions::AllowType) {}
    }

    // Init Tests
    #[test]
    fn test_setvar_no_arguments() {
        let mut action = SetvarAction::new();
        assert_eq!(
            action.init(&mut MockRule, ""),
            Err(ActionError::MissingArguments)
        );
    }

    #[test]
    fn test_setvar_non_tx_variable() {
        let mut action = SetvarAction::new();
        assert!(matches!(
            action.init(&mut MockRule, "PATH_INFO=test"),
            Err(ActionError::InvalidArguments(_))
        ));
    }

    #[test]
    fn test_setvar_tx_set_ok() {
        let mut action = SetvarAction::new();
        assert!(action.init(&mut MockRule, "TX.some=test").is_ok());
    }

    #[test]
    fn test_setvar_tx_without_key_fails() {
        let mut action = SetvarAction::new();
        assert!(matches!(
            action.init(&mut MockRule, "TX=test"),
            Err(ActionError::InvalidArguments(_))
        ));
    }

    #[test]
    fn test_setvar_tx_with_empty_key_fails() {
        let mut action = SetvarAction::new();
        assert!(matches!(
            action.init(&mut MockRule, "TX. =test"),
            Err(ActionError::InvalidArguments(_))
        ));
    }

    // Evaluate Tests
    #[test]
    fn test_setvar_set_simple_value() {
        let mut action = SetvarAction::new();
        action.init(&mut MockRule, "TX.key=value").unwrap();

        let mut tx = MockTransaction::new();
        action.evaluate(&MockRule, &mut tx);

        assert_eq!(tx.get_tx_value("key"), Some("value".to_string()));
    }

    #[test]
    fn test_setvar_set_empty_value() {
        let mut action = SetvarAction::new();
        action.init(&mut MockRule, "TX.key").unwrap();

        let mut tx = MockTransaction::new();
        action.evaluate(&MockRule, &mut tx);

        assert_eq!(tx.get_tx_value("key"), Some("".to_string()));
    }

    #[test]
    fn test_setvar_arithmetic_add() {
        let mut tx = MockTransaction::new();

        // Set initial value
        let mut action1 = SetvarAction::new();
        action1.init(&mut MockRule, "TX.score=5").unwrap();
        action1.evaluate(&MockRule, &mut tx);

        // Add 3
        let mut action2 = SetvarAction::new();
        action2.init(&mut MockRule, "TX.score=+3").unwrap();
        action2.evaluate(&MockRule, &mut tx);

        assert_eq!(tx.get_tx_value("score"), Some("8".to_string()));
    }

    #[test]
    fn test_setvar_arithmetic_subtract() {
        let mut tx = MockTransaction::new();

        // Set initial value
        let mut action1 = SetvarAction::new();
        action1.init(&mut MockRule, "TX.score=10").unwrap();
        action1.evaluate(&MockRule, &mut tx);

        // Subtract 3
        let mut action2 = SetvarAction::new();
        action2.init(&mut MockRule, "TX.score=-3").unwrap();
        action2.evaluate(&MockRule, &mut tx);

        assert_eq!(tx.get_tx_value("score"), Some("7".to_string()));
    }

    #[test]
    fn test_setvar_arithmetic_add_to_zero() {
        let mut tx = MockTransaction::new();

        // Add to non-existent variable (should start at 0)
        let mut action = SetvarAction::new();
        action.init(&mut MockRule, "TX.score=+5").unwrap();
        action.evaluate(&MockRule, &mut tx);

        assert_eq!(tx.get_tx_value("score"), Some("5".to_string()));
    }

    #[test]
    fn test_setvar_arithmetic_negative_result() {
        let mut tx = MockTransaction::new();

        // Set to -5
        let mut action1 = SetvarAction::new();
        action1.init(&mut MockRule, "TX.score=-5").unwrap();
        action1.evaluate(&MockRule, &mut tx);

        // Add 5 (should be 0)
        let mut action2 = SetvarAction::new();
        action2.init(&mut MockRule, "TX.score=+5").unwrap();
        action2.evaluate(&MockRule, &mut tx);

        assert_eq!(tx.get_tx_value("score"), Some("0".to_string()));
    }

    #[test]
    fn test_setvar_non_numeric_plus_literal() {
        let mut action = SetvarAction::new();
        action
            .init(&mut MockRule, "TX.key=+++expected_value")
            .unwrap();

        let mut tx = MockTransaction::new();
        action.evaluate(&MockRule, &mut tx);

        // Non-numeric value after + should be treated as literal
        assert_eq!(
            tx.get_tx_value("key"),
            Some("+++expected_value".to_string())
        );
    }

    #[test]
    fn test_setvar_non_numeric_minus_literal() {
        let mut action = SetvarAction::new();
        action
            .init(&mut MockRule, "TX.key=----expected_value")
            .unwrap();

        let mut tx = MockTransaction::new();
        action.evaluate(&MockRule, &mut tx);

        // Non-numeric value after - should be treated as literal
        assert_eq!(
            tx.get_tx_value("key"),
            Some("----expected_value".to_string())
        );
    }

    #[test]
    fn test_setvar_remove() {
        let mut tx = MockTransaction::new();

        // Set value
        let mut action1 = SetvarAction::new();
        action1.init(&mut MockRule, "TX.key=value").unwrap();
        action1.evaluate(&MockRule, &mut tx);
        assert_eq!(tx.get_tx_value("key"), Some("value".to_string()));

        // Remove it
        let mut action2 = SetvarAction::new();
        action2.init(&mut MockRule, "!TX.key").unwrap();
        action2.evaluate(&MockRule, &mut tx);
        assert_eq!(tx.get_tx_value("key"), None);
    }

    #[test]
    fn test_setvar_case_insensitive_key() {
        let mut action = SetvarAction::new();
        action.init(&mut MockRule, "TX.MyKey=value").unwrap();

        let mut tx = MockTransaction::new();
        action.evaluate(&MockRule, &mut tx);

        // Keys are lowercased
        assert_eq!(tx.get_tx_value("mykey"), Some("value".to_string()));
        assert_eq!(tx.get_tx_value("MyKey"), Some("value".to_string()));
    }

    #[test]
    fn test_setvar_action_type() {
        let action = SetvarAction::new();
        assert_eq!(action.action_type(), ActionType::Nondisruptive);
    }
}
