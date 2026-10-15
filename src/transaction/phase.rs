// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Phase evaluation: running one phase's rules against a transaction, and the flow state
//! the rules' actions change while they run.

use std::collections::{BTreeMap, BTreeSet};

use super::{Interruption, Transaction};
use crate::RuleVariable;
use crate::actions::AllowType;
use crate::rules::VariableException;
use crate::types::{RuleEngineStatus, RulePhase};

/// What phase evaluation reads and the rules' actions change while rules run.
#[derive(Debug)]
pub(super) struct FlowState {
    /// The interruption, by a disruptive action or a body limit
    interruption: Option<Interruption>,

    /// Rules of the current phase still to skip (`skip`)
    skip: i32,

    /// Label of the `SecMarker` to skip to (`skipAfter`); empty for none
    skip_after: String,

    /// Rules skipped because of an `allow` action
    allow: AllowType,

    /// Rules removed for this transaction (`ctl:ruleRemoveById`, `ByTag`, `ByMsg`)
    removed_rules: BTreeSet<i32>,

    /// Keys removed from rules for this transaction (`ctl:ruleRemoveTarget*`), by rule id
    removed_targets: BTreeMap<i32, Vec<(RuleVariable, VariableException)>>,
}

impl FlowState {
    /// The flow state of a transaction no rule has run for.
    pub(super) fn new() -> Self {
        Self {
            interruption: None,
            skip: 0,
            skip_after: String::new(),
            allow: AllowType::Unset,
            removed_rules: BTreeSet::new(),
            removed_targets: BTreeMap::new(),
        }
    }
}

impl Transaction {
    /// Whether `phase` runs now, as Go Coraza decides: not with the rule engine `Off`, nor
    /// once the transaction is interrupted, and in order: a body phase only right after
    /// its headers phase, the others once. A phase that runs becomes the last phase.
    pub(super) fn begin_phase(&mut self, phase: RulePhase) -> bool {
        if self.rule_engine == RuleEngineStatus::Off || self.flow.interruption.is_some() {
            return false;
        }
        let in_order = match phase {
            RulePhase::RequestBody => self.last_phase == Some(RulePhase::RequestHeaders),
            RulePhase::ResponseBody => self.last_phase == Some(RulePhase::ResponseHeaders),
            _ => self.last_phase.is_none_or(|last| last < phase),
        };
        if in_order {
            self.last_phase = Some(phase);
        }
        in_order
    }

    /// Evaluates the WAF's rules of `phase`, in order, if the transaction has a WAF.
    ///
    /// Evaluation stops at an interruption, but in the logging phase, and at an `allow`;
    /// rules of other phases, rules `ctl` removed and rules `skip` or `skipAfter` skip are
    /// passed over. Disruptive actions take effect if the rule engine is `On` when they run,
    /// as an earlier rule's `ctl:ruleEngine` may have changed it.
    pub(super) fn run_phase(&mut self, phase: RulePhase) {
        let Some(rules) = self.rules.clone() else {
            return;
        };

        for rule in rules.get_rules() {
            if self.flow.interruption.is_some() && phase != RulePhase::Logging {
                break;
            }
            // An earlier `allow` skips the rest of this phase
            if self.is_allowed(phase) {
                break;
            }
            // Rules with phase Unknown (0) always run
            if rule.phase() != RulePhase::Unknown && rule.phase() != phase {
                continue;
            }
            if self.is_rule_removed(rule.metadata().id) {
                continue;
            }
            // Rules are skipped up to the marker, which is skipped too
            if !self.flow.skip_after.is_empty() {
                if rule.is_sec_marker(&self.flow.skip_after) {
                    self.flow.skip_after.clear();
                }
                continue;
            }
            if self.flow.skip > 0 {
                self.flow.skip -= 1;
                continue;
            }

            self.reset_matched_vars();
            rule.evaluate(self);
        }

        // As in Go Coraza, `allow:phase` and `skip` end with the phase; `skipAfter` doesn't
        if self.flow.allow == AllowType::Phase {
            self.flow.allow = AllowType::Unset;
        }
        self.flow.skip = 0;
    }

    /// The interruption, if a disruptive action or a body limit interrupted the transaction.
    pub fn interruption(&self) -> Option<&Interruption> {
        self.flow.interruption.as_ref()
    }

    /// Interrupts the transaction on behalf of a disruptive action of rule `rule_id`, if the
    /// rule engine is `On`, as Go Coraza does.
    pub(crate) fn interrupt(&mut self, rule_id: i32, action: &str, status: i32, data: &str) {
        if self.rule_engine == RuleEngineStatus::On {
            self.flow.interruption = Some(Interruption {
                rule_id: rule_id as usize,
                action: action.to_string(),
                status: status as u16,
                data: data.to_string(),
            });
        }
    }

    /// Interrupts the transaction for a body over its limit (`Reject`), as Go Coraza does:
    /// with `deny` and `status`, outside any rule.
    pub(super) fn interrupt_for_body_limit(&mut self, status: u16) -> Interruption {
        let interruption = Interruption {
            rule_id: 0,
            action: "deny".to_string(),
            status,
            data: String::new(),
        };
        self.flow.interruption = Some(interruption.clone());
        interruption
    }

    /// Records an `allow` action, if the rule engine is `On`, as Go Coraza does; see
    /// [`AllowType`] for which rules it skips.
    pub(crate) fn allow(&mut self, allow: AllowType) {
        if self.rule_engine == RuleEngineStatus::On {
            self.flow.allow = allow;
        }
    }

    /// Whether an earlier `allow` action skips the rules of `phase` still to be evaluated.
    fn is_allowed(&self, phase: RulePhase) -> bool {
        match self.flow.allow {
            AllowType::Unset => false,
            AllowType::All | AllowType::Phase => phase != RulePhase::Logging,
            AllowType::Request => {
                matches!(phase, RulePhase::RequestHeaders | RulePhase::RequestBody)
            }
        }
    }

    /// Skips the next `count` rules of the phase, as `skip` does.
    pub(crate) fn set_skip(&mut self, count: i32) {
        self.flow.skip = count;
    }

    /// Skips the rules up to the `SecMarker` labelled `marker`, as `skipAfter` does.
    pub(crate) fn set_skip_after(&mut self, marker: impl Into<String>) {
        self.flow.skip_after = marker.into();
    }

    /// Removes rule `id` for this transaction only, as `ctl:ruleRemoveById` does.
    pub(crate) fn remove_rule_by_id(&mut self, id: i32) {
        self.flow.removed_rules.insert(id);
    }

    /// Whether rule `rule_id` was removed for this transaction.
    pub(crate) fn is_rule_removed(&self, rule_id: i32) -> bool {
        self.flow.removed_rules.contains(&rule_id)
    }

    /// Excludes the keys of `variable` that `exception` matches from rule `rule_id`, for
    /// this transaction, as `ctl:ruleRemoveTarget*` does.
    pub(crate) fn remove_rule_target(
        &mut self,
        rule_id: i32,
        variable: RuleVariable,
        exception: VariableException,
    ) {
        self.flow
            .removed_targets
            .entry(rule_id)
            .or_default()
            .push((variable, exception));
    }

    /// Whether `key` of `variable` was excluded from rule `rule_id` for this transaction.
    pub(crate) fn is_rule_target_removed(
        &self,
        rule_id: i32,
        variable: RuleVariable,
        key: &str,
    ) -> bool {
        self.flow
            .removed_targets
            .get(&rule_id)
            .is_some_and(|targets| {
                targets
                    .iter()
                    .any(|(removed, exception)| *removed == variable && exception.matches(key))
            })
    }
}
