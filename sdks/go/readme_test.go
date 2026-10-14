package verifier_test

import (
	"os"
	"strings"
	"testing"
)

// TestReadmeQuickstartIsTheExample keeps the README quickstart runnable: its Go block must be
// byte-identical to example_test.go, which `go test` compiles and runs against its Output.
func TestReadmeQuickstartIsTheExample(t *testing.T) {
	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	example, err := os.ReadFile("example_test.go")
	if err != nil {
		t.Fatal(err)
	}
	_, section, found := strings.Cut(string(readme), "## Quickstart\n")
	if !found {
		t.Fatal("README.md has no Quickstart section")
	}
	_, block, found := strings.Cut(section, "```go\n")
	if !found {
		t.Fatal("the README Quickstart section has no go block")
	}
	block, _, found = strings.Cut(block, "```\n")
	if !found {
		t.Fatal("the README Quickstart go block is not closed")
	}
	if block != string(example) {
		t.Fatal("the README Quickstart go block differs from example_test.go; copy the file into the README")
	}
}
