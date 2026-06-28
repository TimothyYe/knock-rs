use std::process::Command;

fn main() {
    // Re-run when the VERSION override changes (e.g. the Docker build-arg).
    println!("cargo:rerun-if-env-changed=VERSION");

    // Resolve the reported version, most authoritative source first:
    //   1. An explicit `VERSION` env/build-arg (set by the Docker release build).
    //   2. The exact git tag, so binaries built from a release tag report it.
    //   3. The Cargo.toml version plus the commit hash for local dev builds.
    let version = std::env::var("VERSION")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(git_tag)
        .unwrap_or_else(|| match commit_hash() {
            Some(hash) => format!("{} ({hash})", env!("CARGO_PKG_VERSION")),
            None => env!("CARGO_PKG_VERSION").to_string(),
        });

    println!("cargo:rustc-env=VERSION={version}");
}

fn git_tag() -> Option<String> {
    run_git(&["describe", "--tags", "--exact-match"])
}

fn commit_hash() -> Option<String> {
    run_git(&["rev-parse", "--short", "HEAD"])
}

fn run_git(args: &[&str]) -> Option<String> {
    Command::new("git")
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}
