# Dockerfile for SSH3 integration tests.
#
# Expects the build context directory to contain:
#   ssh3-server, ssh3-client, ssh3-session  (pre-built binaries)
#   run_tests.sh                             (test harness)
#
# The Rust test driver (`docker_integration.rs`) prepares this context by
# compiling binaries inside a `rust:1-bookworm` container (to match the
# runtime glibc), then assembles the build context.
#
# Usage (handled automatically by the test driver):
#   docker run --rm ssh3-test

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY ssh3-server /usr/local/bin/ssh3-server
COPY ssh3-client /usr/local/bin/ssh3-client
COPY ssh3-session /usr/local/bin/ssh3-session
COPY run_tests.sh /run_tests.sh

RUN chmod +x /run_tests.sh /usr/local/bin/*

ENV RUST_LOG=info

ENTRYPOINT ["/run_tests.sh"]
