package jsontransformer

import (
	"testing"

	"github.com/DefangLabs/secret-detector/pkg/transformers/tests"
)

var testCases = []tests.TestCase{
	{"illegal json - empty input", "", nil},
	{"illegal json - simple string", "hello world", nil},
	{"illegal json - double quoted string", `"hello world"`, nil},
	{"illegal json - single quoted string", `'hello world'`, nil},
	{"illegal json - missing bracket", `{"key": "value"`, nil},
	{"illegal json - wrong brackets", `["key": "value"]`, nil},
	{"illegal json - missing key quotes", `{key: "value"}`, nil},
	{"illegal json - missing value quotes", `{"key": value}`, nil},
	{"illegal json - wrong separator", `{"key" = "value"}`, nil},
	{"illegal json - missing comma", `{"k1": "v1" "k2": "v2"}`, nil},
	{"illegal json - redundant comma", `{"key": "value", }`, nil},
	{"empty json", `{}`, map[string]string{}},
	{"value types", `{"s": "a string", "i": 10, "neg": -10, "f": 3.14, "e": 1e3, "b1": true, "b2": false, "u": "\u003a\u0029", "nil": null}`,
		map[string]string{"s": "a string", "i": "10", "neg": "-10", "f": "3.14", "e": "1000", "b1": "true", "b2": "false", "u": ":)", "nil": ""}},
	{"special characters", `{
"spa ce": "val ue",
"ta\tb": "val\tue",
"new\nline": "val\nue",
"sla/sh": "val/ue",
"back\\slash": "val\\ue",
"quo\"te": "val\"ue"
}`,
		map[string]string{
			"spa ce":      "val ue",
			"ta\tb":       "val\tue",
			"new\nline":   "val\nue",
			"sla/sh":      "val/ue",
			"back\\slash": "val\\ue",
			"quo\"te":     "val\"ue",
		}},
	{"nesting objects", `
{
  "a": {
    "1": {"a": "v1"},
    "2": "v2"
  },
  "b": "v3"
}`,
		map[string]string{"a.1.a": "v1", "a.2": "v2", "b": "v3"}},
	{"arrays", `
{
  "arr1": [1,2,3],
  "arr2": [
    {"1": {"a": "v1"} },
    {"2": "v2"},
    "3"]
}`,
		map[string]string{
			"arr1[0]":     "1",
			"arr1[1]":     "2",
			"arr1[2]":     "3",
			"arr2[0].1.a": "v1",
			"arr2[1].2":   "v2",
			"arr2[2]":     "3",
		}},
	{"json with CR/LF",
		`{"k1": "v1",` + "\r\n" + `"k2": "v2"}`,
		map[string]string{"k1": "v1", "k2": "v2"}},
}

var jsonTransformer = NewTransformer()

func TestTransform(t *testing.T) {
	tests.TestTransform(t, jsonTransformer, testCases)
}
