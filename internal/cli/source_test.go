package cli

import "os"

// readSource reads a file from this package's directory.
//
// Used by the gate tests to assert that a command file contains no write
// calls. Reading the source rather than inferring from behaviour is deliberate:
// the property is "this file cannot write", and a behavioural test would only
// show that this particular path did not happen to write today.
//
// The path is resolved relative to the package directory, which for a test is
// the directory the source lives in.
func readSource(name string) (string, error) {
	b, err := os.ReadFile(name)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
