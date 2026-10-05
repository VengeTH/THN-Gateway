//go:build linux

package lab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
	"time"
)

// acceptPollInterval is how often the serve helper checks for its stop file
// while it is waiting for a connection.
const acceptPollInterval = 200 * time.Millisecond

// # Why the tests re-execute their own binary
//
// A TCP probe has to run *inside* a network namespace, and the process running
// the test is in none of them. Binding a socket to a namespace requires being
// in it, so there is no way to write a probe as an ordinary function.
//
// The usual answer is to run a helper binary, which means the repository would
// carry a second program whose only job is to dial a socket. This file is the
// other answer: the test binary re-executes itself with `-test.run` naming one
// test, and that test behaves as the helper when — and only when — it was
// given helper arguments.
//
// The guard against a false result is the argument check. With no arguments
// after `--`, TestLabHelperProcess skips, so the ordinary test run exercises
// nothing here and cannot report a pass it did not achieve.

// helperMarker prefixes every machine-readable line the helper prints.
//
// Prefixed rather than printed bare because the Go test harness writes its own
// lines to the same stream; a consumer looks for this and finds exactly one
// line, instead of hoping the output happens to be valid JSON on its own.
const helperMarker = "THNLAB "

// helperTestName is how the helper is selected when the binary re-executes.
const helperTestName = "TestLabHelperProcess"

// TestLabHelperProcess is the helper the live probes run.
//
// It has three jobs, chosen by the first argument after `--`:
//
//	connect <host:port> <token>  dial, send a token, report what happened
//	serve <host:port> <report>   listen, and record each peer it accepts
//
// When re-executed for the ordinary suite — no arguments after `--` — it skips,
// so this file contributes nothing to a normal `go test ./...`.
func TestLabHelperProcess(t *testing.T) {
	args := helperArgs()
	if len(args) == 0 {
		t.Skip("not running as a lab helper; this test is invoked only by the M6.2 harness")
	}

	switch args[0] {
	case "connect":
		runConnectHelper(t, args)
	case "serve":
		runServeHelper(t, args)
	default:
		t.Fatalf("unknown lab helper mode %q", args[0])
	}
}

// helperArgs returns the arguments that follow the `--` separator.
//
// The separator is what makes this safe: Go's flag parsing stops at the first
// non-flag argument, so the helper's own arguments can never be mistaken for
// testing flags, and the flag set never sees them.
func helperArgs() []string {
	for i, a := range os.Args {
		if a == "--" {
			return os.Args[i+1:]
		}
	}
	return nil
}

// runConnectHelper dials one endpoint and reports the outcome.
//
// It prints the local address it bound and the source address the far end
// reported seeing. Those two together are what turns "a connection happened"
// into "a connection happened, from this address, and arrived as that one".
func runConnectHelper(t *testing.T, args []string) {
	if len(args) != 3 {
		t.Fatalf("connect takes <endpoint> <token>, got %v", args[1:])
	}
	endpoint, token := args[1], args[2]

	var report struct {
		Reachable      bool   `json:"reachable"`
		SourceAddress  string `json:"source_address"`
		ObservedSource string `json:"observed_source"`
		Error          string `json:"error"`
	}

	start := time.Now()
	dialer := net.Dialer{Timeout: helperDialTimeout}
	conn, err := dialer.DialContext(context.Background(), "tcp", endpoint)
	if err != nil {
		report.Error = err.Error()
		emitHelperReport(report)
		t.Logf("connect %s failed: %v", endpoint, err)
		return
	}
	defer conn.Close()

	if local := conn.LocalAddr(); local != nil {
		if tcp, ok := local.(*net.TCPAddr); ok {
			report.SourceAddress = tcp.IP.String()
		}
	}

	_ = conn.SetDeadline(time.Now().Add(helperDialTimeout))
	if _, err := conn.Write([]byte(token + "\n")); err != nil {
		report.Error = fmt.Sprintf("writing request: %v", err)
		emitHelperReport(report)
		return
	}

	// The endpoint answers with the source address it saw. Reading it is what
	// makes a NAT assertion possible from this side of the connection.
	var reply string
	if err := conn.SetReadDeadline(time.Now().Add(helperDialTimeout)); err == nil {
		if _, err := fmt.Fscanln(conn, &reply); err == nil {
			report.ObservedSource = reply
		}
	}

	report.Reachable = true
	emitHelperReport(report)
	t.Logf("connect %s succeeded in %s from %s; endpoint observed %s",
		endpoint, time.Since(start).Round(time.Millisecond), report.SourceAddress, report.ObservedSource)
}

// runServeHelper listens for connections and records each peer address.
//
// It writes one JSON line per accepted connection to the report path and exits
// when the stop file appears, so a test can shut it down deterministically
// instead of leaving a listener behind or waiting out a timeout.
func runServeHelper(t *testing.T, args []string) {
	if len(args) != 4 {
		t.Fatalf("serve takes <endpoint> <report-path> <stop-path>, got %v", args[1:])
	}
	endpoint, reportPath, stopPath := args[1], args[2], args[3]

	ln, err := net.Listen("tcp", endpoint)
	if err != nil {
		t.Fatalf("lab helper listening on %s: %v", endpoint, err)
	}
	defer ln.Close()

	tcp, ok := ln.(*net.TCPListener)
	if !ok {
		t.Fatalf("lab helper listener for %s is %T, want *net.TCPListener", endpoint, ln)
	}

	t.Logf("lab helper serving %s", endpoint)

	for {
		// A deadline rather than a bare Accept. Without one the helper blocks
		// forever when no connection ever arrives, and a stop file nobody
		// re-reads is indistinguishable from a listener that never started.
		if err := tcp.SetDeadline(time.Now().Add(acceptPollInterval)); err != nil {
			t.Fatalf("lab helper setting an accept deadline: %v", err)
		}

		conn, err := tcp.Accept()
		if err != nil {
			if fileExists(stopPath) {
				return
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			t.Fatalf("lab helper accept: %v", err)
		}

		handleServed(t, conn, reportPath)
		if fileExists(stopPath) {
			return
		}
	}
}

// handleServed records one accepted connection and answers it.
func handleServed(t *testing.T, conn net.Conn, reportPath string) {
	defer conn.Close()

	remote := ""
	if tcp, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		remote = tcp.IP.String()
	}

	_ = conn.SetDeadline(time.Now().Add(helperDialTimeout))
	var request string
	if _, err := fmt.Fscanln(conn, &request); err != nil {
		t.Logf("lab helper read from %s: %v", remote, err)
	}

	// Echoing the observed source address back is how the near side learns
	// what the far side saw, which is the NAT assertion.
	if _, err := fmt.Fprintln(conn, remote); err != nil {
		t.Logf("lab helper write to %s: %v", remote, err)
	}

	appendReportLine(t, reportPath, remote, request)
}

// appendReportLine records an accepted peer as one JSON line.
func appendReportLine(t *testing.T, path, peer, request string) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("opening lab report %s: %v", path, err)
	}
	defer f.Close()

	line, err := json.Marshal(map[string]string{"peer": peer, "request": request})
	if err != nil {
		t.Fatalf("encoding lab report line: %v", err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		t.Fatalf("writing lab report line: %v", err)
	}
}

// emitHelperReport prints one machine-readable result line to stdout.
func emitHelperReport(v any) {
	data, err := json.Marshal(v)
	if err != nil {
		return
	}
	fmt.Println(helperMarker + string(data))
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
