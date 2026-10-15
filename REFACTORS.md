# Refactors

Consolidation opportunities found reviewing the crate at `df91834`. Items marked **(probe)** were confirmed by
running a scratch crate against the library; the rest come from reading the code.

Suggested order: 1 → 2 → 3/4 → 5 → 6. Items 1 and 2 let the examples drop their own SecLang loaders and fix the
probed bugs.

## 1. One config type, one way from SecLang to a `Waf`

- [x] **Merge the two `WafConfig` types.**
  - `config::WafConfig` (`src/config.rs:32`, `with_*` builder) and `seclang::WafConfig` (`src/seclang/waf_config.rs:39`,
    public fields) model the same thing with different defaults: rule engine `On` (`config.rs:105`) vs `Off`
    (`waf_config.rs:114`).
  - `tests/e2e_seclang.rs:19` exists only to copy 9 of the seclang config's 23 fields across.
  - Only 5 of `config::WafConfig`'s 20 fields reach a `Transaction` (`src/waf.rs:167`); the rest are stored and at
    most validated. Keep only fields the engine reads.
  - Done: one plain-data `config::WafConfig` (public fields, `Default` with the Go defaults). Kept every field a
    SecLang directive sets, so directives aren't silently dropped; removed the fields nothing sets or reads
    (`response_body_mime_types`, `audit_log_parts`, `audit_log_format`, `argument_separator`, `tmp_dir`).
- [x] **Merge the two `AuditEngineStatus` enums.** `coraza::AuditEngineStatus` (`src/types/waf.rs:17`) and
  `coraza::seclang::AuditEngineStatus` (`src/seclang/waf_config.rs:13`) are distinct types **(probe)**.
  - Done with the config merge: the seclang copy went with `seclang::WafConfig`.
- [ ] **Make `seclang::Parser` compile rules.** It handles no `SecRule`/`SecAction`/`SecMarker`, so
  `examples/ftw_server.rs:281` and `examples/ftw_server_async.rs:273` each carry a second SecLang reader
  (`process_lines`, `parse_directive`). The two already differ on line continuations, and `ftw_server.rs` never calls
  `link_chains()`.
- [ ] **Split `Waf` into `WafBuilder` → `Waf`.** `Waf` is builder and runtime at once: 9
  `Arc::get_mut(..).expect("Cannot modify rules after sharing with transactions")` in `src/waf.rs`, and
  `link_chains()` is documented as "MUST be called". `WafBuilder` takes `&mut` with no panics; `build()` links chains
  and returns an immutable `Waf`.

## 2. Rule state stored twice

- [ ] **Rename `actions::Rule` to `RuleMetadata`.** It collides with `rules::Rule`, which already imports it under
  that alias (`src/actions/mod.rs:163`, `src/rules/rule.rs:14`).
- [ ] **Resolve `t:` into the chain evaluation uses.** `t:` stores names in `metadata.transformations`
  (`src/actions/special.rs:177`); evaluation reads `rules::Rule.transformations: TransformationChain`
  (`src/rules/rule.rs:63`), which nothing in `src/` populates. There is no name → transformation lookup. **(probe)**
  `@streq admin` with `t:lowercase` does not match `ADMIN`.
- [ ] **Wire or remove `capture`.** It sets `metadata.capture`, which nothing reads. **(probe)** `tx.capturing()`
  stays `false`.
- [ ] **Keep one representation of chains.** Chain role lives in `has_chain`, a `parent_id` where 0 means "none",
  and `chain: Option<Box<Rule>>`. `parent_id` is only assigned in tests (`src/rules/rule.rs:507/546/585`).
  **(probe)** A chain parent's `setvar` never runs. Derive the role from position, pass it down during evaluation,
  drop `parent_id`/`has_chain`.

## 3. `TransactionState` trait

- [ ] **Remove the trait, or at least its default bodies.** Defined in `src/operators/macros.rs:16`, about 20
  methods, mostly no-op defaults, one production impl, 14 test mocks. The defaults hide gaps: `Transaction` never
  implements `set_allow_type`, so `allow` does nothing (`src/actions/disruptive.rs:180`). **(probe)** `allow` then
  `deny` in phase 1 still denies with 403.
  - Preferred: actions and operators take `&mut Transaction` (`Transaction::new` is cheap for tests).
  - Minimum: no default bodies, and move the trait into `transaction`.

## 4. `RuleVariable` → transaction data mapped three times

- [ ] **One exhaustive mapping.** `get_collection` (`src/transaction/mod.rs:387`, 17 variables), `get_variable`
  (`:1337`, 17) and `collection_mut` (`:1449`, 7) each end in `_ => None`. `FILES*`, `REQUEST_BODY`, `REQUEST_XML`,
  `MULTIPART_*` and `RESPONSE_*` are populated but unreachable from rules. **(probe)** Confirmed for `REQUEST_BODY`
  and `FILES`. Replace with one `match` without `_` returning `enum CollectionRef { Single(&Single), Map(&Map) }`,
  plus a `_mut` twin; derive `get_variable` from it.
- [ ] **Collapse the collection traits.** `Collection`, `SingleCollection`, `Keyed`, `MapCollection` cover two
  concrete types; calling `Map::add` requires importing `MapCollection`. Make the methods inherent; keep at most one
  trait if `ConcatKeyed` needs it.

## 5. Name → implementation lookup done five ways

- [ ] **Use a `match` on the lowercased name, next to the type, for every built-in set.** Keep a runtime registry
  only where plugins are actually needed.
  - Directives: `HashMap` rebuilt on every `Parser::new()` (`src/seclang/parser.rs:151`).
  - Actions: 33 one-line factories in a `OnceLock` map (`src/actions/mod.rs`).
  - Operators: `match`, but the operator list is written in four places (`src/rules/operator.rs:21`, 23 `From`
    impls, `src/seclang/operator_parser.rs:179`, re-exports). `IpMatchFromFile` exists but is in neither the enum
    nor the parser. `ParsedOperator` (`operator_parser.rs:43`) duplicates `RuleOperator`.
  - Body processors: global `LazyLock<RwLock<HashMap>>` (`src/body_processors/mod.rs:172`), reached via
    content-type → string → lookup (`src/transaction/mod.rs:1070`). An enum of the five kinds would do;
    `BodyProcessorOptions` upload fields are always `Default`.
  - Transformations: no lookup at all (see item 2).
- [ ] **Remove `actions::register`.** Public, and always panics with `todo!()` (`src/actions/mod.rs:502`).
- [ ] **Parse `ctl` once.** `CtlAction` validates its value, stores the raw string, and re-parses it in `evaluate`
  (`src/actions/ctl.rs:263`). **(probe)** `ctl:ruleEngine=bogus` compiles and is silently ignored. Use data-carrying
  variants such as `CtlCommand::RuleEngine(RuleEngineStatus)`.
- [ ] **Decide: `enum Action` instead of `Box<dyn Action>`.** 20 of 33 action types have an empty `evaluate`; they
  only edit metadata in `init`. `parse(name, arg, &mut RuleMetadata) -> Result<Option<Action>, ActionError>` would
  remove the placeholder `new()` + `init` two-step. This reverses the documented "Why `Box<dyn Action>`?" decision
  at `src/rules/action.rs:18`, so it needs a call first.

## 6. Smaller duplicates

- [ ] **Directive boilerplate and errors.** About 25 directive functions repeat the "requires an argument" check and
  `ParseError` construction; `evaluate_line` then drops that location (`src/seclang/parser.rs:475`). Five
  `{ message: String }` error types in `seclang` (`ParseError`, `CompileError`, `ActionParseError`,
  `OperatorParseError`, `VariableParseError`). Directive functions return a plain message; the dispatcher attaches
  location once; one `seclang` error type.
- [ ] **One URL decoder and one query parser.** `Transaction::url_decode` (`src/transaction/mod.rs:866`) decodes
  `%C3%A9` to `"Ã©"`; `transformations::url_decode` gives `"é"` **(probe)**. `body_processors::urlencoded::parse_query`
  collects into a `HashMap`, losing argument order.
- [ ] **`maybe_remove_quotes` twice:** `src/seclang/action_parser.rs:253` and `src/utils/strings.rs:106`.
- [ ] **Hex helpers four times:** `src/transformations/escape.rs:446`, `src/transformations/encoding.rs:176`,
  `src/operators/validation.rs:267`, `src/utils/strings.rs:59/82`. std has `u8::is_ascii_hexdigit` and
  `char::to_digit(16)`.
- [ ] **Transformation signature defined twice:** `Transformation` (`src/rules/transformation.rs:37`) and
  `TransformationResult` (`src/transformations/mod.rs:37`); the escape transformations return `(String, bool)`
  instead.
- [ ] **Six near-identical `Parse*Error { input }` structs** in `src/types/`.

## Tooling

- [ ] Add `required-features = ["async-server"]` for `ftw_server_async`; `cargo clippy --all-targets` fails without
  it. (`cargo clippy --lib --tests` is clean.)
- [ ] `cargo fmt`: diffs in `src/rules/group.rs` and `src/seclang/operator_parser.rs`.
- [ ] Remove `println!`/`eprintln!` from library code (5 sites, in `actions/deferred.rs`, `rules/group.rs`,
  `seclang/parser.rs`, `transaction/mod.rs`).

## Noticed, not consolidation

- With `multiMatch`, all transformed values are joined with `"|"` and matched once (`src/rules/rule.rs:263`).
