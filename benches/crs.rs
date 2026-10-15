// SPDX-License-Identifier: Apache-2.0

//! CRS benchmarks: ports of Go Coraza's `BenchmarkCRSCompilation`, `BenchmarkCRSSimpleGET`,
//! `BenchmarkCRSSimplePOST` and `BenchmarkCRSLargePOST` (`testing/coreruleset`), with the
//! same configuration and requests, so the two engines can be compared.
//!
//! The rules aren't part of this repository; two environment variables point at them:
//! - `CRS_DIR`: a CRS checkout (Go Coraza benchmarks v4.30.0)
//! - `CORAZA_GO_DIR`: a Go Coraza checkout, for its `coraza.conf-recommended`
//!
//! Relative paths are relative to this repository's root. Without both, the benchmarks are
//! skipped.
//!
//! ```sh
//! CRS_DIR=../coreruleset CORAZA_GO_DIR=../coraza cargo bench --bench crs
//! ```

use std::path::PathBuf;
use std::sync::LazyLock;

use coraza::seclang::Parser;
use coraza::waf::Waf;

#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

/// What Go Coraza's `crsWAF` loads between `coraza.conf-recommended` and CRS.
const TEST_SETTINGS: &str = r#"
SecResponseBodyMimeType text/plain

# Rule 900005 from https://github.com/coreruleset/coreruleset/blob/v4.0/dev/tests/regression/README.md#requirements
SecAction "id:900005,\
  phase:1,\
  nolog,\
  pass,\
  ctl:ruleEngine=DetectionOnly,\
  ctl:ruleRemoveById=910000,\
  setvar:tx.blocking_paranoia_level=4,\
  setvar:tx.crs_validate_utf8_encoding=1,\
  setvar:tx.arg_name_length=100,\
  setvar:tx.arg_length=400,\
  setvar:tx.total_arg_length=64000,\
  setvar:tx.max_num_args=255,\
  setvar:tx.max_file_size=64100,\
  setvar:tx.combined_file_sizes=65535"
"#;

const USER_AGENT: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/537.36 \
                          (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36";

/// The directives of Go Coraza's `crsWAF`, or `None` when `CRS_DIR` or `CORAZA_GO_DIR` is unset.
static DIRECTIVES: LazyLock<Option<String>> = LazyLock::new(|| {
    let dir = |var| std::env::var_os(var).map(PathBuf::from);
    let (crs, coraza) = (dir("CRS_DIR")?, dir("CORAZA_GO_DIR")?);
    Some(format!(
        "Include {}\n{TEST_SETTINGS}\nInclude {}\nInclude {}\n",
        coraza.join("coraza.conf-recommended").display(),
        crs.join("crs-setup.conf.example").display(),
        crs.join("rules").join("*.conf").display(),
    ))
});

static WAF: LazyLock<Waf> = LazyLock::new(compile);

static LARGE_FORM: LazyLock<Vec<u8>> =
    LazyLock::new(|| format!("parameters2=and&other2={}", "a".repeat(10_000)).into_bytes());

fn main() {
    if DIRECTIVES.is_none() {
        eprintln!("skipping the CRS benchmarks: set CRS_DIR and CORAZA_GO_DIR");
        return;
    }
    // Compile the shared WAF now, or the first transaction benchmark's first sample includes it
    LazyLock::force(&WAF);
    divan::main();
}

fn compile() -> Waf {
    let directives = DIRECTIVES
        .as_deref()
        .expect("main checks the directives are set");
    let mut parser = Parser::new();
    parser.from_string(directives).expect("CRS loads");
    parser.into_waf().expect("CRS compiles")
}

/// Runs a whole transaction: a GET without a body when `form` is `None`, otherwise a POST of
/// that urlencoded form.
fn transaction(waf: &Waf, form: Option<&[u8]>) {
    let mut tx = waf.new_transaction();
    tx.process_connection("127.0.0.1", 8080, "127.0.0.1", 8080);
    let method = if form.is_some() { "POST" } else { "GET" };
    tx.process_uri(
        "/some_path/with?parameters=and&other=Stuff",
        method,
        "HTTP/1.1",
    );
    tx.add_request_header("Host", "localhost");
    tx.add_request_header("User-Agent", USER_AGENT);
    tx.add_request_header("Accept", "application/json");
    if form.is_some() {
        tx.add_request_header("Content-Type", "application/x-www-form-urlencoded");
    }
    tx.process_request_headers();
    tx.process_request_body(form.unwrap_or_default());
    tx.add_response_header("Content-Type", "application/json");
    tx.process_response_headers(200, "HTTP/1.1");
    tx.process_response_body(b"");
    tx.process_logging().expect("transaction is logged");
}

// The WAF is returned so that dropping it isn't measured; Go's benchmark leaves it to the GC.
#[divan::bench(sample_count = 20, sample_size = 1)]
fn compilation() -> Waf {
    compile()
}

#[divan::bench]
fn simple_get() {
    transaction(&WAF, None);
}

#[divan::bench]
fn simple_post() {
    transaction(&WAF, Some(b"parameters2=and&other2=Stuff"));
}

#[divan::bench]
fn large_post() {
    transaction(&WAF, Some(&LARGE_FORM));
}
