package verifier

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// TestPublicDocumentation makes Go's native declaration comments a CI gate.
func TestPublicDocumentation(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		for _, declaration := range file.Decls {
			switch node := declaration.(type) {
			case *ast.FuncDecl:
				if ast.IsExported(node.Name.Name) && node.Doc == nil {
					t.Errorf("%s: exported function %s has no documentation", name, node.Name)
				}
			case *ast.GenDecl:
				for _, spec := range node.Specs {
					if item, ok := spec.(*ast.TypeSpec); ok && ast.IsExported(item.Name.Name) && item.Doc == nil && node.Doc == nil {
						t.Errorf("%s: exported type %s has no documentation", name, item.Name)
					}
				}
			}
		}
	}
}
