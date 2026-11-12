use std::path::Path;
use std::process::Command;

#[test]
fn charts_keep_missing_samples_and_small_value_precision() {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/js/charts.test.js");
    let output = match Command::new("node").arg(&script).output() {
        Ok(output) => output,
        Err(error) => {
            eprintln!("skipping chart module checks, node is not available: {error}");
            return;
        }
    };
    assert!(
        output.status.success(),
        "chart module checks failed:\n{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
