package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTestConfigFile(t *testing.T, user, pass string) string {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")

	content := `schema_version: 1
gateway:
  name: test-gateway
network:
  wan: eth0
  lan: eth1
  lan_prefix: 10.77.0.1/24
activation:
  require_physical_presence: true
management:
  enabled: true
  bind_address: "127.0.0.1:8080"
  operator_username: "` + user + `"
  operator_password: "` + pass + `"
`
	if err := os.WriteFile(cfgPath, []byte(content), 0600); err != nil {
		t.Fatalf("writing test config: %v", err)
	}
	return cfgPath
}

func TestManagementAuthStatus(t *testing.T) {
	// 1. Unconfigured
	unconfCfg := writeTestConfigFile(t, "", "")
	var stdout, stderr bytes.Buffer
	env := &Env{
		Stdout: &stdout,
		Stderr: &stderr,
		IsJSON: true,
	}

	code := runManagement(env, []string{"auth", "--config", unconfCfg, "--status"})
	if code != ExitOK {
		t.Fatalf("expected ExitOK, got %v", code)
	}

	var statusDoc map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &statusDoc); err != nil {
		t.Fatalf("unmarshaling json: %v", err)
	}
	if statusDoc["configured"] != false {
		t.Fatalf("expected configured=false, got %v", statusDoc["configured"])
	}

	// 2. Configured
	confCfg := writeTestConfigFile(t, "admin", "secret123")
	stdout.Reset()
	stderr.Reset()

	code = runManagement(env, []string{"auth", "--config", confCfg, "--status"})
	if code != ExitOK {
		t.Fatalf("expected ExitOK, got %v", code)
	}

	statusDoc = nil
	if err := json.Unmarshal(stdout.Bytes(), &statusDoc); err != nil {
		t.Fatalf("unmarshaling json: %v", err)
	}
	if statusDoc["configured"] != true {
		t.Fatalf("expected configured=true, got %v", statusDoc["configured"])
	}
	if statusDoc["username"] != "admin" {
		t.Fatalf("expected username=admin, got %v", statusDoc["username"])
	}
}

func TestManagementAuthLoginUnconfigured(t *testing.T) {
	unconfCfg := writeTestConfigFile(t, "", "")
	var stdout, stderr bytes.Buffer
	env := &Env{
		Stdout: &stdout,
		Stderr: &stderr,
		IsJSON: true,
	}

	code := runManagement(env, []string{"auth", "--config", unconfCfg, "--username", "admin", "--password", "foo"})
	if code != ExitProblems {
		t.Fatalf("expected ExitProblems on unconfigured login, got %v", code)
	}

	var res map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		t.Fatalf("unmarshaling json: %v, output=%s", err, stdout.String())
	}
	if res["authenticated"] != false {
		t.Fatalf("expected authenticated=false, got %v", res["authenticated"])
	}
	if !strings.Contains(res["error"].(string), "not configured") {
		t.Fatalf("expected unconfigured error message, got %v", res["error"])
	}
}

func TestManagementAuthLoginSuccessAndFailure(t *testing.T) {
	confCfg := writeTestConfigFile(t, "admin", "SuperSecretPass99!")

	// Wrong password
	var stdout, stderr bytes.Buffer
	env := &Env{
		Stdout: &stdout,
		Stderr: &stderr,
		IsJSON: true,
	}
	code := runManagement(env, []string{"auth", "--config", confCfg, "--username", "admin", "--password", "wrong"})
	if code != ExitProblems {
		t.Fatalf("expected ExitProblems on wrong password, got %v", code)
	}

	var res map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		t.Fatalf("unmarshaling json: %v", err)
	}
	if res["authenticated"] != false {
		t.Fatalf("expected authenticated=false, got %v", res["authenticated"])
	}

	// Correct password
	stdout.Reset()
	stderr.Reset()
	code = runManagement(env, []string{"auth", "--config", confCfg, "--username", "admin", "--password", "SuperSecretPass99!"})
	if code != ExitOK {
		t.Fatalf("expected ExitOK on correct credentials, got %v (stderr=%s)", code, stderr.String())
	}

	res = nil
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		t.Fatalf("unmarshaling json: %v", err)
	}
	if res["authenticated"] != true {
		t.Fatalf("expected authenticated=true, got %v", res["authenticated"])
	}
	if res["username"] != "admin" {
		t.Fatalf("expected username=admin, got %v", res["username"])
	}
	if res["token"] == nil || res["token"].(string) == "" {
		t.Fatalf("expected session token, got %v", res["token"])
	}
}
