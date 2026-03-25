#!/bin/bash
# SSH3 Docker integration test runner.
#
# Generates TLS certificates, starts an ssh3-server, and runs test scenarios
# against it with ssh3-client.  Prints TAP (Test Anything Protocol) output
# so the Rust test driver can parse results.
#
# Exit code: 0 if all tests pass, 1 otherwise.

set -euo pipefail

CERT_DIR=/tmp/certs
SERVER_ADDR="127.0.0.1"
SERVER_PORT="8443"
# Client connects via "localhost" to match the server's TLS certificate name.
CLIENT_AUTHORITY="localhost:${SERVER_PORT}"
SERVER_PID=""
PASS=0
FAIL=0
TEST_NUM=0

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

cleanup() {
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

generate_certs() {
    mkdir -p "$CERT_DIR"
    openssl ecparam -name prime256v1 -genkey -noout \
        -out "$CERT_DIR/server.key" 2>/dev/null
    openssl req -new -x509 -days 1 \
        -key "$CERT_DIR/server.key" \
        -sha256 \
        -out "$CERT_DIR/server.crt" \
        -subj "/CN=localhost" 2>/dev/null
    echo "# Certificates generated in $CERT_DIR"
}

start_server() {
    local mode="${1:-inprocess}"

    if [ "$mode" = "inprocess" ]; then
        ssh3-server "$CERT_DIR/server.crt" "$CERT_DIR/server.key" \
            --bind "${SERVER_ADDR}:${SERVER_PORT}" 2>/tmp/server.log &
        SERVER_PID=$!
    else
        ssh3-server "$CERT_DIR/server.crt" "$CERT_DIR/server.key" \
            --bind "${SERVER_ADDR}:${SERVER_PORT}" \
            --session-binary /usr/local/bin/ssh3-session 2>/tmp/server.log &
        SERVER_PID=$!
    fi

    # Wait for the server to be ready (up to 5 seconds).
    local retries=50
    while [ $retries -gt 0 ]; do
        if kill -0 "$SERVER_PID" 2>/dev/null; then
            # Server process alive; give it a moment to bind.
            sleep 0.1
            retries=$((retries - 1))
        else
            echo "# Server exited prematurely"
            return 1
        fi
    done
    # Give a final settling pause.
    sleep 0.5
    echo "# Server started (PID=$SERVER_PID) on ${SERVER_ADDR}:${SERVER_PORT}"
}

stop_server() {
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
        SERVER_PID=""
    fi
    # Dump server log for diagnostics.
    if [ -f /tmp/server.log ]; then
        echo "# --- server log ---"
        tail -100 /tmp/server.log | sed 's/^/# /'
        echo "# --- end server log ---"
        rm -f /tmp/server.log
    fi
}

# Run a test case.  Arguments:
#   $1  - test name
#   $2  - expected exit code
#   $3  - expected stdout substring (empty string = skip check)
#   $4+ - client arguments
run_test() {
    local name="$1"; shift
    local expected_exit="$1"; shift
    local expected_stdout="$1"; shift

    TEST_NUM=$((TEST_NUM + 1))

    local actual_stdout=""
    local actual_exit=0

    # Run client with a 10-second timeout.  Capture stderr for diagnostics.
    local tmpstderr
    tmpstderr=$(mktemp)
    actual_stdout=$(timeout 10 "$@" 2>"$tmpstderr") || actual_exit=$?
    local actual_stderr
    actual_stderr=$(cat "$tmpstderr")
    rm -f "$tmpstderr"

    # timeout(1) returns 124 on timeout.
    if [ "$actual_exit" -eq 124 ]; then
        FAIL=$((FAIL + 1))
        echo "not ok $TEST_NUM - $name (timed out after 10s)"
        [ -n "$actual_stderr" ] && echo "#   client stderr: $actual_stderr"
        return
    fi

    local ok=true

    # Check exit code.
    if [ "$actual_exit" -ne "$expected_exit" ]; then
        ok=false
    fi

    # Check stdout substring.
    if [ -n "$expected_stdout" ]; then
        if ! echo "$actual_stdout" | grep -qF "$expected_stdout"; then
            ok=false
        fi
    fi

    if $ok; then
        PASS=$((PASS + 1))
        echo "ok $TEST_NUM - $name"
    else
        FAIL=$((FAIL + 1))
        echo "not ok $TEST_NUM - $name"
        echo "#   expected exit=$expected_exit got=$actual_exit"
        if [ -n "$expected_stdout" ]; then
            echo "#   expected stdout to contain: $expected_stdout"
            echo "#   actual stdout: $actual_stdout"
        fi
    fi
}

# ---------------------------------------------------------------------------
# Test scenarios
# ---------------------------------------------------------------------------

run_session_tests() {
    # 1. exec echo
    run_test "exec echo" 0 "hello" \
        ssh3-client "$CLIENT_AUTHORITY" -u user -p pass "echo hello"

    # 2. exec exit code
    run_test "exec exit code 42" 42 "" \
        ssh3-client "$CLIENT_AUTHORITY" -u user -p pass "exit 42"

    # 3. exec cat with stdin
    run_test "exec cat stdin" 0 "inputdata" \
        sh -c 'echo inputdata | ssh3-client '"$CLIENT_AUTHORITY"' -u user -p pass cat'

    # 4. exec stderr (capture stderr too)
    # For this test, we check exit code only since stderr goes to fd 2.
    run_test "exec stderr" 0 "" \
        ssh3-client "$CLIENT_AUTHORITY" -u user -p pass "echo err >&2"
}

run_pam_tests() {
    # 5. PAM correct credentials — whoami should return testuser
    run_test "pam auth correct" 0 "testuser" \
        ssh3-client "$CLIENT_AUTHORITY" -u testuser -p testpass "whoami"

    # 6. PAM wrong password — should fail (non-zero exit)
    run_test "pam auth wrong password" 101 "" \
        ssh3-client "$CLIENT_AUTHORITY" -u testuser -p wrongpass "whoami"

    # 7. PAM non-existent user — should fail (non-zero exit)
    run_test "pam auth no such user" 101 "" \
        ssh3-client "$CLIENT_AUTHORITY" -u nobody99 -p x "whoami"
}

run_forward_tests() {
    # Start an echo server on port 9999 (reflects input back).
    socat TCP-LISTEN:9999,reuseaddr,fork EXEC:cat &
    local ECHO_PID=$!
    sleep 0.3

    # 8. Local forward (-L): client binds 8888 → server connects to 127.0.0.1:9999.
    # Launch ssh3-client with -L in background, send data through the tunnel, verify.
    ssh3-client "$CLIENT_AUTHORITY" -u user -p pass \
        -L 8888:127.0.0.1:9999 "sleep 5" &
    local FWD_PID=$!
    sleep 1

    local fwd_result
    fwd_result=$(echo "hello-forward" | timeout 5 nc -q1 127.0.0.1 8888 2>/dev/null) || true

    TEST_NUM=$((TEST_NUM + 1))
    if [ "$fwd_result" = "hello-forward" ]; then
        PASS=$((PASS + 1))
        echo "ok $TEST_NUM - local forward (-L)"
    else
        FAIL=$((FAIL + 1))
        echo "not ok $TEST_NUM - local forward (-L)"
        echo "#   expected: hello-forward"
        echo "#   got: $fwd_result"
    fi

    kill "$FWD_PID" 2>/dev/null; wait "$FWD_PID" 2>/dev/null || true

    # 9. Remote forward (-R): client asks server to listen on 7777 → client connects to 127.0.0.1:9999.
    ssh3-client "$CLIENT_AUTHORITY" -u user -p pass \
        -R 7777:127.0.0.1:9999 "sleep 5" &
    local RFWD_PID=$!
    sleep 1

    local rfwd_result
    rfwd_result=$(echo "hello-reverse" | timeout 5 nc -q1 127.0.0.1 7777 2>/dev/null) || true

    TEST_NUM=$((TEST_NUM + 1))
    if [ "$rfwd_result" = "hello-reverse" ]; then
        PASS=$((PASS + 1))
        echo "ok $TEST_NUM - remote forward (-R)"
    else
        FAIL=$((FAIL + 1))
        echo "not ok $TEST_NUM - remote forward (-R)"
        echo "#   expected: hello-reverse"
        echo "#   got: $rfwd_result"
    fi

    kill "$RFWD_PID" 2>/dev/null; wait "$RFWD_PID" 2>/dev/null || true
    kill "$ECHO_PID" 2>/dev/null; wait "$ECHO_PID" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    echo "# SSH3 integration tests"

    # Verify binaries have all required libraries.
    echo "# Checking library dependencies..."
    ldd /usr/local/bin/ssh3-server 2>&1 | grep "not found" && echo "# WARNING: ssh3-server missing libs"
    ldd /usr/local/bin/ssh3-client 2>&1 | grep "not found" && echo "# WARNING: ssh3-client missing libs"
    ldd /usr/local/bin/ssh3-session 2>&1 | grep "not found" && echo "# WARNING: ssh3-session missing libs"

    generate_certs

    echo "# --- Session tests (in-process mode) ---"
    start_server inprocess
    run_session_tests
    stop_server

    echo "# --- PAM tests (child-process mode) ---"
    start_server childprocess
    run_pam_tests
    stop_server

    echo "# --- Forwarding tests (in-process mode) ---"
    start_server inprocess
    run_forward_tests
    stop_server

    # Summary
    local total=$((PASS + FAIL))
    echo "1..$total"
    echo "# $PASS passed, $FAIL failed out of $total tests"

    if [ "$FAIL" -gt 0 ]; then
        exit 1
    fi
}

main "$@"
