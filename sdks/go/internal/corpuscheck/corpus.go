// Package corpuscheck verifies certified input closure and computed verdicts (ADR 0049).
// It is test tooling and has no dependency on the verifier's runtime package.
package corpuscheck

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode/utf16"
)

type Case struct {
	File  string
	Value map[string]any
}
type Run struct {
	t          *testing.T
	root, tree string
	Cases      []Case
	actual     map[string]map[string]any
}

func SHA(body []byte) string {
	sum := sha256.Sum256(body)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
func Decode(body []byte) any {
	var value any
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&value); err != nil {
		panic(err)
	}
	return value
}
func read(path string) []byte {
	body, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	return body
}
func Outcome(c map[string]any) map[string]any {
	if expected, ok := c["expected"]; ok {
		return expected.(map[string]any)
	}
	keys := []string{}
	if valid, ok := c["valid"]; ok {
		keys = []string{"valid"}
		if valid == true {
			keys = append(keys, "normalized")
		}
	} else if _, ok := c["decode_local"]; ok {
		keys = []string{"decode_local", "decode_standard", "envelope_local"}
	} else if _, ok := c["decode"]; ok {
		keys = []string{"decode", "verify"}
	} else {
		panic("case lacks declared outcome schema")
	}
	result := map[string]any{}
	for _, key := range keys {
		value, ok := c[key]
		if !ok {
			panic("missing declared outcome member")
		}
		result[key] = value
	}
	return result
}
func New(t *testing.T, root, tree, pin string) *Run {
	t.Helper()
	raw := read(filepath.Join(root, "index.json"))
	sum := sha256.Sum256(raw)
	if SHA(raw) != pin && hex.EncodeToString(sum[:]) != pin {
		t.Fatal("index SHA mismatch")
	}
	index := Decode(raw).(map[string]any)
	declared := map[string]bool{"index.json": true}
	ids := map[string]bool{}
	cases := []Case{}
	for _, item := range index["files"].([]any) {
		entry := item.(map[string]any)
		name := entry["path"].(string)
		if filepath.IsAbs(name) || filepath.ToSlash(filepath.Clean(name)) != name || strings.HasPrefix(name, "../") || declared[name] {
			t.Fatal("unsafe or duplicate indexed path")
		}
		declared[name] = true
		body := read(filepath.Join(root, name))
		sum = sha256.Sum256(body)
		actual := hex.EncodeToString(sum[:])
		expected := entry["sha256"]
		if value, ok := entry["sha256_base64url"]; ok {
			expected = value
			actual = SHA(body)
		}
		if actual != expected {
			t.Fatalf("%s: file SHA mismatch", name)
		}
		if !strings.HasSuffix(name, ".json") || name == "revision.json" {
			continue
		}
		doc := Decode(body)
		members, ok := doc.([]any)
		if !ok {
			obj := doc.(map[string]any)
			members, _ = obj["cases"].([]any)
			if members == nil {
				members, _ = obj["uri_cases"].([]any)
			}
		}
		if n, ok := entry["cases"]; ok && n.(json.Number).String() != strconv.Itoa(len(members)) {
			t.Fatalf("%s: case count mismatch", name)
		}
		for _, member := range members {
			c := member.(map[string]any)
			id := c["id"].(string)
			if ids[id] {
				t.Fatal("duplicate case ID")
			}
			ids[id] = true
			cases = append(cases, Case{name, c})
		}
	}
	present := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("nonregular corpus input")
		}
		rel, _ := filepath.Rel(root, path)
		present[filepath.ToSlash(rel)] = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(present) != len(declared) {
		t.Fatal("corpus file set mismatch")
	}
	for name := range declared {
		if !present[name] {
			t.Fatal("corpus file set mismatch")
		}
	}
	total := 0
	if n, ok := index["total_cases"]; ok {
		total, _ = strconv.Atoi(string(n.(json.Number)))
	} else {
		for _, key := range []string{"uri_cases", "proof_cases", "attestation_cases", "digest_cases", "assertion_cases", "successor_cases"} {
			if n, ok := index[key]; ok {
				count, _ := strconv.Atoi(string(n.(json.Number)))
				total += count
			}
		}
	}
	if len(cases) != total {
		t.Fatal("total case count mismatch")
	}
	return &Run{t: t, root: root, tree: tree, Cases: cases, actual: map[string]map[string]any{}}
}
func (r *Run) Record(id, file string, actual map[string]any) {
	r.t.Helper()
	if _, ok := r.actual[id]; ok {
		r.t.Fatal("duplicate executed ID")
	}
	for _, c := range r.Cases {
		if c.Value["id"] == id {
			if file != c.File {
				r.t.Fatal("wrong declaring file")
			}
			projection := map[string]any{}
			for key := range Outcome(c.Value) {
				if value, ok := actual[key]; ok {
					projection[key] = value
				}
			}
			r.actual[id] = projection
			return
		}
	}
	r.t.Fatal("unknown executed ID")
}
func Verdict(err error) string {
	if err != nil {
		return "invalid"
	}
	return "valid"
}
func (r *Run) Finish() {
	r.t.Helper()
	if len(r.actual) != len(r.Cases) {
		r.t.Fatal("execution completeness: skipped cases")
	}
	pairs := []any{}
	for _, c := range r.Cases {
		id := c.Value["id"].(string)
		actual, ok := r.actual[id]
		if !ok {
			r.t.Fatal("execution completeness: skipped case")
		}
		if !bytes.Equal(Canonical(actual), Canonical(Outcome(c.Value))) {
			r.t.Errorf("computed outcome %s: got %s want %s", id, Canonical(actual), Canonical(Outcome(c.Value)))
		}
		pairs = append(pairs, []any{id, actual})
	}
	manifest := Decode(read(filepath.Join(r.tree, "verdict-digests.json"))).(map[string]any)
	key, _ := filepath.Rel(r.tree, r.root)
	entry := manifest["corpora"].(map[string]any)[filepath.ToSlash(key)].(map[string]any)
	if manifest["format"] != "bap-corpus-verdict-digests/1" || entry["index_sha256_base64url"] != SHA(read(filepath.Join(r.root, "index.json"))) || entry["case_count"].(json.Number).String() != strconv.Itoa(len(pairs)) {
		r.t.Fatal("verdict manifest binding mismatch")
	}
	digest := SHA(Canonical(pairs))
	r.t.Logf("%s: %d cases, verdict digest %s", filepath.ToSlash(key), len(pairs), digest)
	if entry["verdict_digest_sha256_base64url"] != digest {
		r.t.Fatalf("computed verdict digest mismatch: %s", key)
	}
}

// Canonical implements RFC 8785 for JSON outcomes, including UTF-16 key order and
// ECMAScript's fixed/scientific number thresholds. No protocol wire bounds apply.
func Canonical(value any) []byte {
	switch v := value.(type) {
	case nil:
		return []byte("null")
	case bool:
		if v {
			return []byte("true")
		}
		return []byte("false")
	case string:
		out := []byte{'"'}
		for _, ch := range v {
			switch ch {
			case '"', '\\':
				out = append(out, '\\', byte(ch))
			case '\b':
				out = append(out, '\\', 'b')
			case '\t':
				out = append(out, '\\', 't')
			case '\n':
				out = append(out, '\\', 'n')
			case '\f':
				out = append(out, '\\', 'f')
			case '\r':
				out = append(out, '\\', 'r')
			default:
				if ch < 32 {
					out = append(out, []byte(fmt.Sprintf("\\u%04x", ch))...)
				} else {
					out = append(out, []byte(string(ch))...)
				}
			}
		}
		return append(out, '"')
	case json.RawMessage:
		return Canonical(Decode(v))
	case json.Number:
		n, err := strconv.ParseFloat(string(v), 64)
		if err != nil {
			panic(err)
		}
		return Canonical(n)
	case float64:
		if math.IsInf(v, 0) || math.IsNaN(v) {
			panic("nonfinite JSON outcome")
		}
		if v == 0 {
			return []byte("0")
		}
		format := byte('f')
		if math.Abs(v) < 1e-6 || math.Abs(v) >= 1e21 {
			format = 'e'
		}
		s := strconv.FormatFloat(v, format, -1, 64)
		s = strings.ReplaceAll(strings.ReplaceAll(s, "e-0", "e-"), "e+0", "e+")
		return []byte(s)
	case []any:
		parts := [][]byte{}
		for _, item := range v {
			parts = append(parts, Canonical(item))
		}
		return append(append([]byte{'['}, bytes.Join(parts, []byte{','})...), ']')
	case map[string]any:
		keys := []string{}
		for key := range v {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool {
			a, b := utf16.Encode([]rune(keys[i])), utf16.Encode([]rune(keys[j]))
			for n := 0; n < len(a) && n < len(b); n++ {
				if a[n] != b[n] {
					return a[n] < b[n]
				}
			}
			return len(a) < len(b)
		})
		parts := [][]byte{}
		for _, key := range keys {
			parts = append(parts, append(append(Canonical(key), ':'), Canonical(v[key])...))
		}
		return append(append([]byte{'{'}, bytes.Join(parts, []byte{','})...), '}')
	default:
		body, err := json.Marshal(v)
		if err != nil {
			panic(err)
		}
		return Canonical(Decode(body))
	}
}
