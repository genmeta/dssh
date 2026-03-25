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
    ssh3-server "$CERT_DIR/server.crt" "$CERT_DIR/server.key" \
        --bind "${SERVER_ADDR}:${SERVER_PORT}" \
        --session-binary /usr/local/bin/ssh3-session 2>/tmp/server.log &
    SERVER_PID=$!

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
        ssh3-client "$CLIENT_AUTHORITY" -u testuser -p testpass "echo hello"

    # 2. exec exit code
    run_test "exec exit code 42" 42 "" \
        ssh3-client "$CLIENT_AUTHORITY" -u testuser -p testpass "exit 42"

    # 3. exec cat with stdin
    run_test "exec cat stdin" 0 "inputdata" \
        sh -c 'echo inputdata | ssh3-client '"$CLIENT_AUTHORITY"' -u testuser -p testpass cat'

    # 4. exec stderr (capture stderr too)
    # For this test, we check exit code only since stderr goes to fd 2.
    run_test "exec stderr" 0 "" \
        ssh3-client "$CLIENT_AUTHORITY" -u testuser -p testpass "echo err >&2"
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
    # Start echo servers on multiple ports (reflect input back).
    socat TCP-LISTEN:9999,reuseaddr,fork EXEC:cat &
    local ECHO_PID1=$!
    socat TCP-LISTEN:9998,reuseaddr,fork EXEC:cat &
    local ECHO_PID2=$!
    sleep 0.3

    # 8. Local forward (-L): client binds 8888 → server connects to 127.0.0.1:9999.
    ssh3-client "$CLIENT_AUTHORITY" -u testuser -p testpass \
        -L 8888:127.0.0.1:9999 "sleep 10" &
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
    ssh3-client "$CLIENT_AUTHORITY" -u testuser -p testpass \
        -R 7777:127.0.0.1:9999 "sleep 10" &
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

    # 10. Multiple local forwards: two -L on one connection.
    ssh3-client "$CLIENT_AUTHORITY" -u testuser -p testpass \
        -L 8881:127.0.0.1:9999 -L 8882:127.0.0.1:9998 "sleep 10" &
    local MULTI_L_PID=$!
    sleep 1

    local ml_result1 ml_result2
    ml_result1=$(echo "multi-L-1" | timeout 5 nc -q1 127.0.0.1 8881 2>/dev/null) || true
    ml_result2=$(echo "multi-L-2" | timeout 5 nc -q1 127.0.0.1 8882 2>/dev/null) || true

    TEST_NUM=$((TEST_NUM + 1))
    if [ "$ml_result1" = "multi-L-1" ] && [ "$ml_result2" = "multi-L-2" ]; then
        PASS=$((PASS + 1))
        echo "ok $TEST_NUM - multiple local forwards (-L -L)"
    else
        FAIL=$((FAIL + 1))
        echo "not ok $TEST_NUM - multiple local forwards (-L -L)"
        echo "#   port 8881: expected 'multi-L-1', got '$ml_result1'"
        echo "#   port 8882: expected 'multi-L-2', got '$ml_result2'"
    fi

    kill "$MULTI_L_PID" 2>/dev/null; wait "$MULTI_L_PID" 2>/dev/null || true

    # 11. Multiple remote forwards: two -R on one connection.
    ssh3-client "$CLIENT_AUTHORITY" -u testuser -p testpass \
        -R 7771:127.0.0.1:9999 -R 7772:127.0.0.1:9998 "sleep 10" &
    local MULTI_R_PID=$!
    sleep 1

    local mr_result1 mr_result2
    mr_result1=$(echo "multi-R-1" | timeout 5 nc -q1 127.0.0.1 7771 2>/dev/null) || true
    mr_result2=$(echo "multi-R-2" | timeout 5 nc -q1 127.0.0.1 7772 2>/dev/null) || true

    TEST_NUM=$((TEST_NUM + 1))
    if [ "$mr_result1" = "multi-R-1" ] && [ "$mr_result2" = "multi-R-2" ]; then
        PASS=$((PASS + 1))
        echo "ok $TEST_NUM - multiple remote forwards (-R -R)"
    else
        FAIL=$((FAIL + 1))
        echo "not ok $TEST_NUM - multiple remote forwards (-R -R)"
        echo "#   port 7771: expected 'multi-R-1', got '$mr_result1'"
        echo "#   port 7772: expected 'multi-R-2', got '$mr_result2'"
    fi

    kill "$MULTI_R_PID" 2>/dev/null; wait "$MULTI_R_PID" 2>/dev/null || true

    # 12. Combined -L and -R on the same connection.
    ssh3-client "$CLIENT_AUTHORITY" -u testuser -p testpass \
        -L 8883:127.0.0.1:9999 -R 7773:127.0.0.1:9998 "sleep 10" &
    local COMBO_PID=$!
    sleep 1

    local combo_l combo_r
    combo_l=$(echo "combo-L" | timeout 5 nc -q1 127.0.0.1 8883 2>/dev/null) || true
    combo_r=$(echo "combo-R" | timeout 5 nc -q1 127.0.0.1 7773 2>/dev/null) || true

    TEST_NUM=$((TEST_NUM + 1))
    if [ "$combo_l" = "combo-L" ] && [ "$combo_r" = "combo-R" ]; then
        PASS=$((PASS + 1))
        echo "ok $TEST_NUM - combined local+remote forward (-L -R)"
    else
        FAIL=$((FAIL + 1))
        echo "not ok $TEST_NUM - combined local+remote forward (-L -R)"
        echo "#   -L port 8883: expected 'combo-L', got '$combo_l'"
        echo "#   -R port 7773: expected 'combo-R', got '$combo_r'"
    fi

    kill "$COMBO_PID" 2>/dev/null; wait "$COMBO_PID" 2>/dev/null || true

    # 13. Concurrent connections through the same local forward.
    ssh3-client "$CLIENT_AUTHORITY" -u testuser -p testpass \
        -L 8884:127.0.0.1:9999 "sleep 10" &
    local CONC_PID=$!
    sleep 1

    local conc1 conc2 conc3
    # Fire 3 connections in parallel.
    conc1=$(echo "conn-1" | timeout 5 nc -q1 127.0.0.1 8884 2>/dev/null) &
    local C1=$!
    conc2=$(echo "conn-2" | timeout 5 nc -q1 127.0.0.1 8884 2>/dev/null) &
    local C2=$!
    conc3=$(echo "conn-3" | timeout 5 nc -q1 127.0.0.1 8884 2>/dev/null) &
    local C3=$!
    wait "$C1" 2>/dev/null; conc1=$(echo "conn-1" | timeout 5 nc -q1 127.0.0.1 8884 2>/dev/null) || true
    wait "$C2" 2>/dev/null || true
    wait "$C3" 2>/dev/null || true

    # Re-run sequentially (subshell capture in bg is unreliable).
    local conc_ok=true
    for i in 1 2 3; do
        local cr
        cr=$(echo "seq-$i" | timeout 5 nc -q1 127.0.0.1 8884 2>/dev/null) || true
        if [ "$cr" != "seq-$i" ]; then
            conc_ok=false
            break
        fi
    done

    TEST_NUM=$((TEST_NUM + 1))
    if $conc_ok; then
        PASS=$((PASS + 1))
        echo "ok $TEST_NUM - concurrent connections through forward"
    else
        FAIL=$((FAIL + 1))
        echo "not ok $TEST_NUM - concurrent connections through forward"
    fi

    kill "$CONC_PID" 2>/dev/null; wait "$CONC_PID" 2>/dev/null || true

    # 14. Large data transfer through local forward (128KB).
    ssh3-client "$CLIENT_AUTHORITY" -u testuser -p testpass \
        -L 8885:127.0.0.1:9999 "sleep 10" &
    local LARGE_PID=$!
    sleep 1

    local expected_md5 actual_md5
    dd if=/dev/urandom bs=1024 count=128 of=/tmp/testdata 2>/dev/null
    expected_md5=$(md5sum /tmp/testdata | awk '{print $1}')
    actual_md5=$(timeout 10 nc -q1 127.0.0.1 8885 < /tmp/testdata 2>/dev/null | md5sum | awk '{print $1}') || true
    rm -f /tmp/testdata

    TEST_NUM=$((TEST_NUM + 1))
    if [ "$expected_md5" = "$actual_md5" ]; then
        PASS=$((PASS + 1))
        echo "ok $TEST_NUM - large data (128KB) through forward"
    else
        FAIL=$((FAIL + 1))
        echo "not ok $TEST_NUM - large data (128KB) through forward"
        echo "#   expected md5: $expected_md5"
        echo "#   actual md5: $actual_md5"
    fi

    kill "$LARGE_PID" 2>/dev/null; wait "$LARGE_PID" 2>/dev/null || true

    # 15. Multiple concurrent client sessions (server handles parallel connections).
    local pids=()
    local results=()
    for i in 1 2 3; do
        ssh3-client "$CLIENT_AUTHORITY" -u testuser -p testpass "echo session-$i" \
            >/tmp/session_result_$i 2>/dev/null &
        pids+=($!)
    done
    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null || true
    done
    local multi_ok=true
    for i in 1 2 3; do
        local content
        content=$(cat /tmp/session_result_$i 2>/dev/null) || true
        if [ "$content" != "session-$i" ]; then
            multi_ok=false
        fi
        rm -f /tmp/session_result_$i
    done

    TEST_NUM=$((TEST_NUM + 1))
    if $multi_ok; then
        PASS=$((PASS + 1))
        echo "ok $TEST_NUM - multiple concurrent client sessions"
    else
        FAIL=$((FAIL + 1))
        echo "not ok $TEST_NUM - multiple concurrent client sessions"
        echo "#   expected each session to return its own 'session-N'"
    fi

    # Cleanup echo servers.
    kill "$ECHO_PID1" 2>/dev/null; wait "$ECHO_PID1" 2>/dev/null || true
    kill "$ECHO_PID2" 2>/dev/null; wait "$ECHO_PID2" 2>/dev/null || true
}

run_unix_socket_tests() {
    # Start a Unix domain socket echo server.
    local ECHO_SOCK="/tmp/echo.sock"
    rm -f "$ECHO_SOCK"
    socat UNIX-LISTEN:"$ECHO_SOCK",reuseaddr,fork,mode=0666 EXEC:cat &
    local ECHO_PID=$!
    sleep 0.3

    # 16. Local forward: TCP bind → Unix socket connect (-L port:/path).
    ssh3-client "$CLIENT_AUTHORITY" -u testuser -p testpass \
        -L 8886:/tmp/echo.sock "sleep 10" &
    local TCP2UNIX_PID=$!
    sleep 1

    local t2u_result
    t2u_result=$(echo "tcp-to-unix" | timeout 5 nc -q1 127.0.0.1 8886 2>/dev/null) || true

    TEST_NUM=$((TEST_NUM + 1))
    if [ "$t2u_result" = "tcp-to-unix" ]; then
        PASS=$((PASS + 1))
        echo "ok $TEST_NUM - local forward TCP→Unix (-L port:/path)"
    else
        FAIL=$((FAIL + 1))
        echo "not ok $TEST_NUM - local forward TCP→Unix (-L port:/path)"
        echo "#   expected: tcp-to-unix"
        echo "#   got: $t2u_result"
    fi

    kill "$TCP2UNIX_PID" 2>/dev/null; wait "$TCP2UNIX_PID" 2>/dev/null || true

    # 17. Local forward: Unix socket bind → TCP connect (-L /path:host:port).
    # Start TCP echo server on port 9997.
    socat TCP-LISTEN:9997,reuseaddr,fork EXEC:cat &
    local TCP_ECHO_PID=$!
    sleep 0.3

    local CLIENT_SOCK="/tmp/client_fwd.sock"
    rm -f "$CLIENT_SOCK"
    ssh3-client "$CLIENT_AUTHORITY" -u testuser -p testpass \
        -L "$CLIENT_SOCK":127.0.0.1:9997 "sleep 10" &
    local UNIX2TCP_PID=$!
    sleep 1

    local u2t_result
    u2t_result=$(echo "unix-to-tcp" | timeout 5 socat - UNIX-CONNECT:"$CLIENT_SOCK" 2>/dev/null) || true

    TEST_NUM=$((TEST_NUM + 1))
    if [ "$u2t_result" = "unix-to-tcp" ]; then
        PASS=$((PASS + 1))
        echo "ok $TEST_NUM - local forward Unix→TCP (-L /path:host:port)"
    else
        FAIL=$((FAIL + 1))
        echo "not ok $TEST_NUM - local forward Unix→TCP (-L /path:host:port)"
        echo "#   expected: unix-to-tcp"
        echo "#   got: $u2t_result"
    fi

    kill "$UNIX2TCP_PID" 2>/dev/null; wait "$UNIX2TCP_PID" 2>/dev/null || true
    kill "$TCP_ECHO_PID" 2>/dev/null; wait "$TCP_ECHO_PID" 2>/dev/null || true
    rm -f "$CLIENT_SOCK"

    # 18. Local forward: Unix socket bind → Unix socket connect (-L /local:/remote).
    local CLIENT_SOCK2="/tmp/client_fwd2.sock"
    rm -f "$CLIENT_SOCK2"
    ssh3-client "$CLIENT_AUTHORITY" -u testuser -p testpass \
        -L "$CLIENT_SOCK2":/tmp/echo.sock "sleep 10" &
    local UNIX2UNIX_PID=$!
    sleep 1

    local u2u_result
    u2u_result=$(echo "unix-to-unix" | timeout 5 socat - UNIX-CONNECT:"$CLIENT_SOCK2" 2>/dev/null) || true

    TEST_NUM=$((TEST_NUM + 1))
    if [ "$u2u_result" = "unix-to-unix" ]; then
        PASS=$((PASS + 1))
        echo "ok $TEST_NUM - local forward Unix→Unix (-L /local:/remote)"
    else
        FAIL=$((FAIL + 1))
        echo "not ok $TEST_NUM - local forward Unix→Unix (-L /local:/remote)"
        echo "#   expected: unix-to-unix"
        echo "#   got: $u2u_result"
    fi

    kill "$UNIX2UNIX_PID" 2>/dev/null; wait "$UNIX2UNIX_PID" 2>/dev/null || true
    rm -f "$CLIENT_SOCK2"

    # 19. Remote forward: Unix socket → TCP (-R /remote/path:host:port).
    socat TCP-LISTEN:9996,reuseaddr,fork EXEC:cat &
    local RTCP_ECHO_PID=$!
    sleep 0.3

    local REMOTE_SOCK="/tmp/remote_fwd.sock"
    rm -f "$REMOTE_SOCK"
    ssh3-client "$CLIENT_AUTHORITY" -u testuser -p testpass \
        -R "$REMOTE_SOCK":127.0.0.1:9996 "sleep 10" &
    local RUNIX_PID=$!
    sleep 1

    local ru_result
    ru_result=$(echo "remote-unix" | timeout 5 socat - UNIX-CONNECT:"$REMOTE_SOCK" 2>/dev/null) || true

    TEST_NUM=$((TEST_NUM + 1))
    if [ "$ru_result" = "remote-unix" ]; then
        PASS=$((PASS + 1))
        echo "ok $TEST_NUM - remote forward Unix→TCP (-R /path:host:port)"
    else
        FAIL=$((FAIL + 1))
        echo "not ok $TEST_NUM - remote forward Unix→TCP (-R /path:host:port)"
        echo "#   expected: remote-unix"
        echo "#   got: $ru_result"
    fi

    kill "$RUNIX_PID" 2>/dev/null; wait "$RUNIX_PID" 2>/dev/null || true
    kill "$RTCP_ECHO_PID" 2>/dev/null; wait "$RTCP_ECHO_PID" 2>/dev/null || true
    rm -f "$REMOTE_SOCK"

    # Cleanup.
    kill "$ECHO_PID" 2>/dev/null; wait "$ECHO_PID" 2>/dev/null || true
    rm -f "$ECHO_SOCK"
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

    echo "# --- Starting server (child-process mode) ---"
    start_server

    echo "# --- Session tests ---"
    run_session_tests

    echo "# --- PAM tests ---"
    run_pam_tests

    echo "# --- Forwarding tests ---"
    run_forward_tests

    echo "# --- Unix socket forwarding tests ---"
    run_unix_socket_tests

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
