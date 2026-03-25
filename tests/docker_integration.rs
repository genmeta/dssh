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

    // Build inside Docker, mounting the workspace and an output volume.
    let status = Command::new("docker")
        .args([
            "run",
            "--rm",
            // Mount workspace (read-only) so all path deps are available.
            "-v",
            &format!("{}:/workspace:ro", workspace_root.display()),
            // Mount a writable overlay for the build output.
            "-v",
            &format!("{}:/output", out_dir.display()),
            // Use named volumes for cargo caches (persist across runs).
            "-v",
            "ssh3-test-cargo-registry:/usr/local/cargo/registry",
            "-v",
            "ssh3-test-cargo-target:/build-target",
            "-e",
            "CARGO_TARGET_DIR=/build-target",
            "-w",
            &format!("/workspace/{repo_name}"),
            "rust:1-bookworm",
            "sh",
            "-c",
            // Copy source to a writable location, build, copy binaries out.
            &format!(
                "cp -a /workspace /build && \
                 cd /build/{repo_name} && \
                 cargo build --examples && \
                 cp /build-target/debug/examples/ssh3-server \
                    /build-target/debug/examples/ssh3-client \
                    /build-target/debug/examples/ssh3-session \
                    /output/",
                repo_name = repo_name,
            ),
        ])
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
        eprintln!("--- container stderr ---\n{stderr}--- end stderr ---");
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
