//! Docker-based integration tests for SSH3.
//!
//! These tests compile the example binaries inside a `rust:1-bookworm`
//! container (to match the runtime glibc), assemble a Docker build context,
//! build a minimal runtime image, and run test scenarios inside it.
//! The container test script outputs TAP (Test Anything Protocol) which this
//! driver parses.
//!
//! Run with:
//! ```sh
//! cargo test --test docker_integration -- --ignored
//! ```
//!
//! Prerequisites:
//! - Docker daemon running

use std::path::{Path, PathBuf};
use std::process::Command;
use std::{env, fs};

const IMAGE_NAME: &str = "ssh3-integration-test";

/// Locate the repository root (where Cargo.toml lives).
fn repo_root() -> PathBuf {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    PathBuf::from(manifest_dir)
}

/// Build example binaries inside a `rust:1-bookworm` Docker container.
///
/// The workspace root (parent of genmeta-ssh3) is volume-mounted so that
/// path dependencies (h3x, gm-quic, etc.) are available.
///
/// Returns the host path to the directory containing the built binaries.
fn build_examples_in_docker(repo: &Path) -> PathBuf {
    let workspace_root = repo.parent().expect("repo has no parent directory");
    let repo_name = repo.file_name().unwrap().to_str().unwrap();

    // Output directory on host for the built binaries.
    let out_dir = repo.join("target").join("docker-build");
    fs::create_dir_all(&out_dir).expect("failed to create docker-build output dir");

    // Prefer mounting the host cargo registry (read-only) so builds don't
    // need network access.  Fall back to named Docker volumes when the host
    // registry directory does not exist.
    let cargo_home = env::var("CARGO_HOME")
        .unwrap_or_else(|_| format!("{}/.cargo", env::var("HOME").unwrap()));
    let host_registry = PathBuf::from(&cargo_home).join("registry");
    let use_host_registry = host_registry.is_dir();

    let mut args: Vec<String> = vec![
        "run".into(),
        "--rm".into(),
        // Mount workspace (read-only) so all path deps are available.
        "-v".into(),
        format!("{}:/workspace:ro", workspace_root.display()),
        // Mount a writable overlay for the build output.
        "-v".into(),
        format!("{}:/output", out_dir.display()),
    ];

    if use_host_registry {
        // Mount host cargo registry read-only to avoid network downloads.
        args.extend([
            "-v".into(),
            format!("{}:/usr/local/cargo/registry:ro", host_registry.display()),
        ]);
    } else {
        // Fall back to named Docker volumes (requires network).
        args.extend([
            "-v".into(),
            "ssh3-test-cargo-registry:/usr/local/cargo/registry".into(),
        ]);
    }

    args.extend([
        "-v".into(),
        "ssh3-test-cargo-target:/build-target".into(),
        "-e".into(),
        "CARGO_TARGET_DIR=/build-target".into(),
        "-w".into(),
        format!("/workspace/{repo_name}"),
        "rust:1-bookworm".into(),
        "sh".into(),
        "-c".into(),
        // Copy source (excluding target/ and .git/ dirs) to a writable
        // location, build, and copy binaries out. Uses tar with --exclude
        // to avoid installing extra packages.
        format!(
            "cd /workspace && \
             tar cf - --exclude='target' --exclude='.git' . | (mkdir -p /build && cd /build && tar xf -) && \
             apt-get update && apt-get install -y --no-install-recommends libpam0g-dev libclang-dev && \
             cd /build/{repo_name} && \
             cargo build --examples --features pam && \
             cp /build-target/debug/examples/ssh3-server \
                /build-target/debug/examples/ssh3-client \
                /build-target/debug/examples/ssh3-session \
                /output/",
            repo_name = repo_name,
        ),
    ]);

    // Build inside Docker, mounting the workspace and an output volume.
    let status = Command::new("docker")
        .args(&args)
        .status()
        .expect("failed to run docker for building examples");

    assert!(
        status.success(),
        "docker build of examples failed (exit code: {status})"
    );

    out_dir
}

/// Assemble the Docker build context and build the runtime image.
fn docker_build(repo: &Path, binaries_dir: &Path) {
    let context_dir = repo.join("target").join("docker-context");
    let _ = fs::remove_dir_all(&context_dir);
    fs::create_dir_all(&context_dir).expect("failed to create docker-context");

    // Copy binaries into context.
    for name in ["ssh3-server", "ssh3-client", "ssh3-session"] {
        fs::copy(binaries_dir.join(name), context_dir.join(name))
            .unwrap_or_else(|e| panic!("failed to copy {name}: {e}"));
    }

    // Copy Dockerfile and test script into context.
    fs::copy(
        repo.join("tests/docker/Dockerfile"),
        context_dir.join("Dockerfile"),
    )
    .expect("failed to copy Dockerfile");
    fs::copy(
        repo.join("tests/docker/run_tests.sh"),
        context_dir.join("run_tests.sh"),
    )
    .expect("failed to copy run_tests.sh");

    let status = Command::new("docker")
        .args(["build", "-t", IMAGE_NAME, "."])
        .current_dir(&context_dir)
        .status()
        .expect("failed to run docker build");

    assert!(status.success(), "docker build failed");
}

/// Run the Docker container and return its stdout.
fn docker_run() -> (String, bool) {
    let output = Command::new("docker")
        .args(["run", "--rm", IMAGE_NAME])
        .output()
        .expect("failed to run docker run");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if !stderr.is_empty() {
        // Print container stderr in both stdout and stderr for visibility
        // (cargo test captures stdout for failed tests, but may truncate stderr).
        println!("--- container stderr (last 200 lines) ---");
        for line in stderr.lines().rev().take(200).collect::<Vec<_>>().into_iter().rev() {
            println!("{line}");
        }
        println!("--- end container stderr ---");
    }

    (stdout, output.status.success())
}

/// Parse TAP output and assert all tests passed.
fn assert_tap_output(tap: &str) {
    println!("--- TAP output ---\n{tap}--- end TAP ---");

    let mut total_tests = 0;
    let mut passed = 0;
    let mut failed = 0;

    for line in tap.lines() {
        let line = line.trim();
        if line.starts_with("ok ") {
            passed += 1;
            total_tests += 1;
        } else if line.starts_with("not ok ") {
            failed += 1;
            total_tests += 1;
            eprintln!("FAILED: {line}");
        }
    }

    assert!(total_tests > 0, "no TAP test results found in output");
    assert_eq!(failed, 0, "{failed} test(s) failed out of {total_tests}");
    println!("{passed}/{total_tests} tests passed");
}

#[test]
#[ignore = "requires Docker daemon; slow (compiles in container)"]
fn docker_integration() {
    let repo = repo_root();

    eprintln!("Building example binaries inside Docker (rust:1-bookworm)...");
    let binaries_dir = build_examples_in_docker(&repo);

    eprintln!("Building runtime Docker image...");
    docker_build(&repo, &binaries_dir);

    eprintln!("Running integration tests in container...");
    let (tap_output, container_success) = docker_run();
    assert_tap_output(&tap_output);
    assert!(container_success, "container exited with non-zero status");
}
