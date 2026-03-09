# Coraza Rust Port - Progress Log

**Note:** Crate renamed from `coraza-rs` to `coraza` on 2026-03-09.

## Porting Strategy & Guidelines

### Trait Usage - Avoid Over-Abstraction

**IMPORTANT:** Do not blindly convert Go interfaces to Rust traits. Follow these guidelines:

1. **Only Create Traits for Multiple Implementations**
   - Check the Go codebase: how many implementations of the interface exist?
   - If there's only ONE production implementation, **do not create a trait**
   - Use concrete types instead of traits

2. **Test-Only Interfaces Should Use Generics**
   - If an interface exists "only to make testing easier" (one real impl + one mock):
     - **Use generics (monomorphization)** instead of traits
     - Let the compiler generate optimized code for each concrete type
     - This achieves **zero-cost abstraction** with no runtime overhead
   - Example: `TransactionState` has only one production impl + test mocks → use `<TX: TransactionState>`

3. **Dynamic Dispatch Requires Explicit Approval**
   - If you determine that runtime dynamic dispatch (`&dyn Trait`) is necessary:
     - **Explicitly inform the user before implementing**
     - Explain why static dispatch (generics) won't work
     - Provide justification for the runtime overhead
   - Most cases can be solved with generics or enums

4. **Performance Philosophy**
   - Prefer: Concrete types > Generics > Trait objects
   - Always choose the leftmost option that satisfies the requirements
   - Rust's strength is zero-cost abstractions - leverage it

### Example: TransactionState

```rust
// ✅ GOOD: Generic static dispatch (what we implemented)
pub trait TransactionState {
    fn get_variable(&self, variable: RuleVariable, key: Option<&str>) -> Option<String>;
}

impl Operator for Eq {
    fn evaluate<TX: TransactionState>(&self, tx: Option<&TX>, input: &str) -> bool {
        // Compiler inlines everything - zero runtime cost
    }
}

// ❌ BAD: Dynamic dispatch (unnecessary overhead)
impl Operator for Eq {
    fn evaluate(&self, tx: Option<&dyn TransactionState>, input: &str) -> bool {
        // Vtable lookup every call - unnecessary cost
    }
}

// 🤔 QUESTION FOR USER: Need runtime polymorphism
// "I need to store different operator types in a Vec - should I use Box<dyn Operator>?"
// → User can decide if the flexibility is worth the cost
```

### Test Parity Requirements

- **All test cases** from the Go implementation must be ported
- This guarantees behavioral compatibility with the original implementation
- Document any intentional deviations in the porting log

## Phase 1: Foundation - Types and Enums

### Completed ✅

#### 1. RuleSeverity (src/types/severity.rs)
- **Date:** 2026-03-09
- **Source:** `coraza/types/severity.go`
- **Tests:** 8/8 passing
- **Features:**
  - 8 severity levels (Emergency through Debug)
  - String representation (`as_str()`, `Display`)
  - Integer conversion (`as_int()`)
  - Parsing from strings and numbers (`FromStr`)
  - Case-insensitive parsing
  - Full error handling with `ParseSeverityError`
  - Ordering support
- **Improvements over Go:**
  - Type-safe enum instead of int
  - Const methods
  - Standard trait implementations (Display, FromStr, Ord, Hash)
  - Doc tests

#### 2. RulePhase (src/types/phase.rs)
- **Date:** 2026-03-09
- **Source:** `coraza/types/phase.go`
- **Tests:** 8/8 passing
- **Features:**
  - 6 phase variants (Unknown, RequestHeaders, RequestBody, ResponseHeaders, ResponseBody, Logging)
  - String representation (`as_str()`, `Display`)
  - Integer conversion (`as_int()`)
  - Validity checking (`is_valid()`)
  - Parsing from strings and numbers (`FromStr`)
  - Special names: "request" → RequestBody, "response" → ResponseBody, "logging" → Logging
  - Full error handling with `ParsePhaseError`
  - Ordering support
- **Improvements over Go:**
  - Type-safe enum instead of int
  - Const methods
  - Additional `is_valid()` helper
  - Idiomatic range checking with `contains()`

#### 3. RuleVariable (src/types/variables.rs)
- **Date:** 2026-03-09
- **Source:** `coraza/types/variables/variables.go`, `coraza/internal/variables/variables.go`
- **Tests:** 8/8 passing
- **Features:**
  - 96 variable variants covering all WAF transaction data
  - String representation (`name()`, `Display`)
  - Integer conversion (`as_u8()`)
  - Parsing from strings (`FromStr`)
  - Case-insensitive parsing
  - Full error handling with `ParseVariableError`
  - Comprehensive variable set:
    - Request variables (URI, headers, body, method, etc.)
    - Response variables (status, headers, body, etc.)
    - Server variables (addr, name, port)
    - Collection variables (ARGS, FILES, COOKIES, etc.)
    - Time variables (TIME_*, epoch, formatted)
    - Special variables (TX, RULE, GEO, ENV)
    - Multipart/file upload variables
    - Compatibility variables (legacy ModSecurity)
- **Improvements over Go:**
  - Type-safe enum instead of byte with iota
  - Const `name()` method with lookup table for perfect sync
  - Safe `from_u8()` helper with bounds checking
  - Compile-time exhaustiveness checking
  - Roundtrip test validates all 96 variants
  - Better documentation with variable categories

#### 4. WAF Engine Types (src/types/waf.rs)
- **Date:** 2026-03-09
- **Source:** `coraza/types/waf.go`, `coraza/types/waf_test.go`
- **Tests:** 39/39 passing
- **Features:**
  - **AuditEngineStatus** - Controls audit logging (On, Off, RelevantOnly)
  - **RuleEngineStatus** - Controls rule processing (On, DetectionOnly, Off)
  - **BodyLimitAction** - Action when body exceeds limit (ProcessPartial, Reject)
  - **AuditLogPart** - Log sections A-K, Z (Header, RequestHeaders, RequestBody, etc.)
    - Char-based enum (A, B, C, ..., K, Z)
    - `from_char()` and `as_char()` conversions
    - `is_mandatory()` helper for parts A and Z
    - `TryFrom<char>` trait implementation
  - **AuditLogParts** - Type alias for `Vec<AuditLogPart>`
  - **`parse_audit_log_parts()`** - Validates and parses audit log part strings
    - Must start with 'A' and end with 'Z' (mandatory)
    - Validates all middle parts are valid (B-K)
    - Returns error for invalid parts or missing mandatory parts
  - **`apply_audit_log_parts()`** - Modifies audit log parts
    - Addition mode: "+E" adds part E
    - Removal mode: "-E" removes part E
    - Absolute mode: "ABCDEFZ" sets exact parts
    - Maintains canonical order (BCDEFGHIJK)
    - Prevents modification of mandatory parts A and Z
  - All types support parsing from strings (case-insensitive where applicable)
  - Full error handling with custom error types
- **Improvements over Go:**
  - Type-safe enums instead of integers
  - Const methods
  - `is_mandatory()` helper for audit log parts
  - Better char/enum integration for AuditLogPart
  - Uses `HashSet` for efficient deduplication in `apply_audit_log_parts()`

#### 5. String Utilities (src/utils/strings.rs)
- **Date:** 2026-03-09
- **Source:** `coraza/internal/strings/strings.go`
- **Tests:** 11/11 passing
- **Functions:**
  - **`random_string(n)`** - Thread-safe pseudorandom string generation
  - **`valid_hex(x)`** - Validate hexadecimal characters (uses `is_ascii_hexdigit()`)
  - **`x2c(what)`** - Convert hex string to byte (uses `u8::from_str_radix()`)
  - **`maybe_remove_quotes(s)`** - Remove matching surrounding quotes
  - **`unescape_quoted_string(s)`** - Unescape `\"` in SecLang strings
  - **`wrap_unsafe(buf)`** - Zero-copy byte slice to string conversion
  - ~~`InSlice`~~ - Not ported, use Rust's `slice.contains()` directly
- **Dependencies:**
  - `fastrand = "2.0"` - Lightweight RNG (no dependencies)
- **Improvements over Go:**
  - Leverages stdlib: `is_ascii_hexdigit()`, `from_str_radix()`, `starts_with()`, `ends_with()`
  - More idiomatic with `&str` instead of String where possible
  - Panic on invalid input to `x2c()` instead of silent errors
  - Cleaner code using stdlib utilities

### Quality Metrics - Phase 1
- ✅ All tests passing (74/74)
- ✅ Clippy clean (no warnings)
- ✅ Full documentation
- ✅ Doc tests included
- ✅ **Test parity verified** - All Go tests from Phase 1 ported
- ✅ **Phase 1 Complete!** All foundation types and utilities ported

## Phase 2: Transformations - Simple String Operations

### Completed ✅

#### 1. Simple String Transformations (src/transformations/simple.rs)
- **Date:** 2026-03-09
- **Source:** `coraza/internal/transformations/*.go`
- **Tests:** 10/10 passing
- **Functions:**
  - **`lowercase()`** - Convert to lowercase
  - **`uppercase()`** - Convert to uppercase
  - **`trim()`** - Remove leading/trailing whitespace
  - **`trim_left()`** - Remove leading whitespace
  - **`trim_right()`** - Remove trailing whitespace
  - **`compress_whitespace()`** - Collapse multiple whitespace to single space
  - **`remove_whitespace()`** - Remove all whitespace
  - **`url_decode()`** - URL percent-decoding and + to space
- **Features:**
  - All transformations return `(String, bool, Option<Error>)` tuple
  - Boolean indicates if data was changed
  - Errors are for logging only, don't stop execution
  - Fast path optimization: early exit if no transformation needed
  - Uses existing `valid_hex()` and `x2c()` utilities
  - ModSecurity-compatible whitespace handling (C++ isspace)
- **Improvements over Go:**
  - Used `.position()` instead of manual loops for finding special characters
  - Iterator-based implementation for `do_compress_whitespace()`
  - More idiomatic Rust patterns (filter, position, etc.)
  - Zero-copy where possible (trim returns string slice reference in Go, owned in Rust)

### Quality Metrics
- ✅ All tests passing (84/84, +10 new)
- ✅ Clippy clean (no warnings)
- ✅ Full documentation with examples
- ✅ Doc tests included
- ✅ Test parity verified - All Go test cases ported

#### 2. Encoding/Decoding Transformations (src/transformations/encoding.rs)
- **Date:** 2026-03-09
- **Source:** `coraza/internal/transformations/*.go`
- **Tests:** 9/9 passing
- **Functions:**
  - **`length()`** - Returns string length as string
  - **`none()`** - Identity transformation (returns input unchanged)
  - **`remove_nulls()`** - Removes NUL bytes (\x00)
  - **`replace_nulls()`** - Replaces NUL bytes with spaces
  - **`hex_encode()`** - Encode to hexadecimal (lowercase)
  - **`hex_decode()`** - Decode from hexadecimal (case-insensitive)
  - **`url_encode()`** - URL encoding (percent-encoding + space to +)
  - **`base64_encode()`** - Standard base64 encoding with padding
- **Features:**
  - Custom base64 encoder (no external dependencies)
  - Custom hex decoder with proper error handling
  - URL encoder matches ModSecurity behavior (only alphanumerics and * unencoded)
  - Fast path optimizations (early exit for empty input, no nulls, etc.)
- **Improvements over Go:**
  - Used `.is_multiple_of()` for cleaner odd length check
  - Used `.div_ceil()` for capacity calculation
  - More idiomatic error handling with Result types
  - Custom base64 implementation avoids dependency

### Quality Metrics - Phase 2
- ✅ All tests passing (93/93, +19 new)
- ✅ Clippy clean (no warnings)
- ✅ Full documentation with examples
- ✅ Doc tests included
- ✅ Test parity verified - All Go test cases ported

#### 3. Hash Functions and Base64 Decode (src/transformations/encoding.rs)
- **Date:** 2026-03-09
- **Source:** `coraza/internal/transformations/*.go`
- **Tests:** 4/4 passing
- **Functions:**
  - **`md5_hash()`** - Computes MD5 hash (returns raw binary, not hex)
  - **`sha1_hash()`** - Computes SHA1 hash (returns raw binary, not hex)
  - **`base64_decode()`** - Base64 decode with partial decoding support
  - **`base64_decode_ext()`** - Lenient base64 decode (ignores whitespace and dots)
- **Dependencies:**
  - `md-5 = "0.10"` - RustCrypto MD5 implementation
  - `sha1 = "0.10"` - RustCrypto SHA1 implementation
- **Features:**
  - Hash functions return raw binary output (matches ModSecurity behavior)
  - Pre-computed hashes for empty strings (optimization)
  - Custom base64 decoder with partial decoding (ModSecurity compatibility)
  - base64_decode stops at first invalid character, returns partial result
  - base64_decode_ext also ignores whitespace and '.' characters
  - Comprehensive test coverage from Go test suite (30+ test cases)
- **Improvements over Go:**
  - Uses industry-standard RustCrypto implementations (audited, well-maintained)
  - Cleaner base64 decode map constant
  - More efficient byte processing with iterators

### Quality Metrics - Phase 2
- ✅ All tests passing (97/97, +4 new)
- ✅ Clippy clean (no warnings)
- ✅ Full documentation with examples
- ✅ Doc tests included
- ✅ Test parity verified - All Go test cases ported
- ✅ **Phase 2 Complete!** All basic transformations ported

## Phase 3: Operators - Rule Matching

### Completed ✅

#### 1. Simple Comparison Operators (src/operators/simple.rs)
- **Date:** 2026-03-09
- **Source:** `coraza/internal/operators/*.go`
- **Tests:** 17/17 passing (unit) + 9/9 passing (doc tests)
- **Operators:**
  - **`eq`** - Numeric equality (converts to i32, compares)
  - **`gt`** - Greater than (numeric)
  - **`ge`** - Greater than or equal (numeric)
  - **`lt`** - Less than (numeric)
  - **`le`** - Less than or equal (numeric)
  - **`streq`** - String equality (case-sensitive)
  - **`contains`** - String contains substring
  - **`begins_with`** - String starts with prefix
  - **`ends_with`** - String ends with suffix
- **Features:**
  - Simple `Operator` trait with `evaluate(&self, input: &str) -> bool`
  - No macro expansion support (simplified version)
  - Invalid integer parsing returns 0 (matches Go's strconv.Atoi)
  - Constructor functions: `eq("10")`, `gt("5")`, etc.
  - Each operator is a struct storing parsed parameter
- **Design:**
  - Trait-based design for operator abstraction
  - Numeric operators use `str::parse::<i32>()` with `unwrap_or(0)`
  - String operators use stdlib: `contains()`, `starts_with()`, `ends_with()`
  - All operators are `Clone` and `Debug`
- **Improvements over Go:**
  - Type-safe operator structs instead of closures
  - No runtime macro parsing overhead (will add later)
  - Clear separation of concerns (trait-based)

### Quality Metrics - Phase 3
- ✅ All tests passing (114/114 unit tests, +17 new)
- ✅ Doc tests passing (9/9 new)
- ✅ Clippy clean (no warnings)
- ✅ Full documentation with examples
- ✅ Test coverage includes edge cases (negatives, invalid input, empty strings)

#### 2. Pattern Matching Operators (src/operators/pattern.rs)
- **Date:** 2026-03-09
- **Source:** `coraza/internal/operators/*.go`
- **Tests:** 19/19 passing (unit) + 4/4 passing (doc tests)
- **Dependencies:**
  - `regex = "1.10"` - RE2-compatible regex engine
  - `aho-corasick = "1.1"` - Multi-pattern string matching
- **Operators:**
  - **`rx`** - Regular expression matching (dotall mode by default)
  - **`pm`** - Phrase matching (case-insensitive, Aho-Corasick algorithm)
  - **`within`** - Check if input is within parameter (inverse of contains)
  - **`strmatch`** - Case-sensitive substring match (alias for contains)
- **Features:**
  - `rx` auto-enables dotall mode `(?s)` for ModSecurity compatibility
  - `pm` uses Aho-Corasick for efficient multi-pattern matching
  - `pm` is case-insensitive by default
  - `within` is the inverse of `contains` (needle in haystack check)
  - No capturing support yet (simplified version)
- **Improvements over Go:**
  - Uses Rust's high-performance `regex` crate (RE2-compatible)
  - Uses `aho-corasick` crate (optimized for multi-pattern)
  - Type-safe error handling for invalid regex patterns
  - No runtime macro parsing overhead

### Quality Metrics - Phase 3
- ✅ All tests passing (133/133 unit tests, +19 new)
- ✅ Doc tests passing (13/13, +4 new)
- ✅ Clippy clean (no warnings)
- ✅ Full documentation with examples
- ✅ Test coverage includes Unicode, dotall mode, case-insensitivity

#### 3. Macro Expansion System (src/operators/macros.rs)
- **Date:** 2026-03-09
- **Source:** `coraza/macro/macro.go`
- **Tests:** 16/16 passing (macro parser) + 156/156 total (all operators updated)
- **Features:**
  - **TransactionState trait** - Interface for variable lookups during rule evaluation
  - **Macro struct** - Parses and expands `%{VARIABLE.key}` syntax with **full static dispatch**
  - **MacroToken** - Internal representation of parsed macro segments
  - **NoTx** - Temporary deprecated convenience type (to be removed after transaction port)
  - Supports plain text, single variables, and multi-variable strings
  - Comprehensive validation (empty braces, malformed syntax, unknown variables)
  - All 13 existing operators updated to support macro expansion:
    - Simple operators: `eq`, `gt`, `ge`, `lt`, `le`, `streq`, `contains`, `begins_with`, `ends_with`
    - Pattern operators: `rx`, `pm`, `within`, `strmatch`
  - Operator trait uses generic type parameter: `fn evaluate<TX: TransactionState>(...)`
  - Caching optimization for operators without macros (pre-compile regex/matchers)
  - Empty string support (empty parameters are valid)
- **Design - Zero-Cost Abstraction:**
  - **Complete static dispatch** - No `&dyn` trait objects anywhere
  - `Macro::new()` parses macro string at operator construction time
  - `Macro::expand<TX>()` uses generics for zero runtime overhead
  - Pattern operators (`rx`, `pm`) cache compiled patterns when no macros present
  - If macro expansion is used, patterns are compiled on-the-fly
  - Fallback behavior: invalid macro syntax returns no match
  - **Compiler inlining:** Full call path `evaluate() → expand() → get_variable()` can be inlined
  - **Minimal monomorphization:** Only one production `TransactionState` type expected (matches Go)
- **Improvements over Go:**
  - Type-safe TransactionState trait (vs interface{})
  - **Zero dynamic dispatch** - true zero-cost abstraction
  - Const methods where possible
  - Compile-time validation of macro syntax
  - Performance optimization with cached patterns
  - Idiomatic error handling with Result types
- **Test Coverage:**
  - Macro parser: 16 tests (empty, plain text, variables, multi-variable, errors)
  - Simple operators: 26 tests (+3 macro expansion tests)
  - Pattern operators: 23 tests (+4 macro expansion tests)
  - All tests include macro expansion scenarios with MockTx

### Quality Metrics - Phase 3 (Updated)
- ✅ All tests passing (156/156 unit tests, +39 new from macro integration)
- ✅ Doc tests passing (56/56)
- ✅ Clippy clean (no warnings)
- ✅ Full documentation with examples
- ✅ Test coverage includes macro expansion, transaction state, caching
- ✅ **Phase 3, Step 3 Complete!** Macro expansion fully integrated

### Next Steps
- [ ] **IMPORTANT - Cleanup After Transaction Port:** Once the production `TransactionState` implementation is ported:
  - Delete `NoTx` struct from `src/operators/macros.rs`
  - Remove all `#[allow(deprecated)]` attributes from:
    - `src/operators/macros.rs` (impl block and test module)
    - `src/operators/mod.rs` (pub use statement)
    - `src/operators/simple.rs` (test module)
    - `src/operators/pattern.rs` (test module)
  - Update all test code to use the production transaction type instead of `NoTx`
  - This cleanup is critical to avoid shipping deprecated convenience types
- [ ] **Phase 3, Step 4:** Add capturing group support for rx and pm operators
- [ ] **Phase 3, Step 5:** Port IP matching operators (ipMatch, ipMatchFromFile)
- [ ] **Phase 4:** Port complex text processing transformations (cmd_line, css_decode, js_decode, html_entity_decode, escape sequences)
