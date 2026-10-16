# Coraza (Rust port)

A Rust port of Go Coraza: a web application firewall that evaluates SecLang rules against HTTP
transactions, aiming at Go Coraza's behaviour.

## Language

### Evaluating rules

**Transaction**:
One HTTP request and its response as the WAF sees them: their variables, and the state of their
phase evaluation.
_Avoid_: request, tx context

**Phase**:
One of the five points (request headers, request body, response headers, response body, logging) at
which a transaction evaluates the rules assigned to it.
_Avoid_: stage, step

**Phase evaluation**:
Running one phase's rules against a transaction: deciding whether the phase runs, checking each rule,
and resetting what only lasts a phase; owned by the transaction.
_Avoid_: rule group eval

**Flow state**:
What phase evaluation reads and actions write while rules run: the skip count, the `skipAfter`
marker, `allow`, the interruption, and the rules `ctl` removed.
_Avoid_: flow control, runtime state

**Rule engine mode**:
`On`, `DetectionOnly` or `Off` (`SecRuleEngine`, changed for one transaction by `ctl:ruleEngine`),
read when an action needs it rather than once per phase.
_Avoid_: engine status, enforcement mode, `rule_engine_on`

**Value**:
What a variable holds for a key: in collections such as `ARGS`, the bytes the request sent,
whether or not they are UTF-8; keys, and single-value variables such as `REQUEST_URI`, are text.
_Avoid_: string, text (for values)

**Body processor**:
The parser (`URLENCODED`, `MULTIPART`, `JSON`, `XML`, `RAW`) that turns a transaction's request or
response body into variables, as `REQBODY_PROCESSOR` or `RES_BODY_PROCESSOR` names it.
_Avoid_: body parser

**Operator**:
The test a rule applies to each value it inspects (`@rx`, `@streq`, `@detectSQLi`, ...); it reads
the transaction's variables but never changes the transaction.
_Avoid_: matcher, check

**Capture**:
A part of a value an operator matched, handed back to its rule, which stores it in `TX.0`–`TX.9`
when the rule has `capture`.
_Avoid_: capture group (that is the regex's), match data

**Disruptive action**:
An action that decides the transaction's outcome (`deny`, `drop`, `redirect`, `allow`, `pass`,
`block`); it runs once its rule's whole chain matched.
_Avoid_: blocking action

**Flow action**:
An action that changes which later rules of the phase run (`skip`, `skipAfter`).

**Interruption**:
The transaction stopped, with a status, by a disruptive action in `On` mode or by a body limit.
_Avoid_: block, intervention, disruption

**Would-be interruption**:
The first interruption a disruptive action would have caused in `DetectionOnly` mode.
_Avoid_: detection-only interruption, potential disruption

**Rule set**:
A WAF's rules in evaluation order (`RuleGroup`), shared by all its transactions and unchanged while
they run.
_Avoid_: rule group

**Error log**:
One line per matched rule with `log`, in Go Coraza's format, handed to the **Connector** through the
WAF's sink as the rule matches.
_Avoid_: debug log (the embedder's, at `SecDebugLogLevel`), match log

**Connector**:
The code embedding the library that feeds transactions from an HTTP server and acts on their
interruptions, such as the FTW examples.
_Avoid_: integration, server

## Relationships

- A WAF has one **Rule set**, shared by all its **Transactions**, compiled from SecLang directives
  only; a **Connector** reads a matched rule's description, but never builds a rule.
- A **Transaction** goes through each **Phase** at most once, in order; **Phase evaluation** runs the
  **Rule set**'s rules of that **Phase**. A body **Phase** runs only right after its headers
  **Phase**; called at any other time, it does nothing.
- Once a **Transaction** has an **Interruption**, no later **Phase** is evaluated but logging, and
  every **Phase** returns that **Interruption**.
- A **Transaction**'s logging **Phase** runs exactly once: when the **Connector** calls it, or when the
  **Transaction** is dropped without it.
- **Flow state** belongs to one **Transaction**, never to the **Rule set**.
- A **Connector** writes a **Transaction**'s variables only through its input calls
  (`process_connection`, `process_uri`, `add_request_header`, `add_*_argument`,
  `add_response_header`, the phase calls), which keep variables derived from others, such as
  `ARGS`, consistent.
- A **Transaction**'s request **Body processor** is chosen by its first `Content-Type`, or by
  `ctl:requestBodyProcessor` before the request body **Phase**; it runs only in that **Phase**, and
  writes only its own variables, while the **Transaction** records its failure in `REQBODY_ERROR`.
- A **Transaction** starts with its WAF's settings (body access and limits, body processor,
  audit engine and parts, debug log level); only a `ctl` action changes them, for that
  **Transaction** alone.
- An **Operator** hands its **Captures** (and `@restpath` its path arguments) back to its rule; the
  rule, not the **Operator**, writes them to the **Transaction**.
- A **Disruptive action** gives an **Interruption** in `On` mode, a **Would-be interruption** in
  `DetectionOnly` mode, and nothing in `Off` mode, as the **Rule engine mode** is when it runs.

## Example dialogue

> **Dev:** "Rule 1 sets `ctl:ruleEngine=DetectionOnly` and rule 2 denies, both in phase 1. Is the
> **Transaction** interrupted?"
> **Domain expert:** "No: the **Rule engine mode** is `DetectionOnly` by the time rule 2's
> **Disruptive action** runs, so it only leaves a **Would-be interruption**, which the audit log's
> relevant-status check uses."
> **Dev:** "And a `skip:1` on the last rule of phase 1?"
> **Domain expert:** "It ends with the **Phase**: the skip count is **Flow state** that only lasts a
> phase. A `skipAfter` whose marker wasn't reached carries over."

## Flagged ambiguities

- "Rule engine on" meant both a per-phase snapshot (`rule_engine_on: bool`, passed down to actions)
  and the transaction's live setting; resolved: the **Rule engine mode** is the live setting only.
