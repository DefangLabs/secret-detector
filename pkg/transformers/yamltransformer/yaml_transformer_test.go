package yamltransformer

import (
	"testing"

	"github.com/DefangLabs/secret-detector/pkg/transformers/tests"
)

var testCases = []tests.TestCase{
	{"empty input", "", map[string]string{}},
	{"illegal structure - text", "this is not a yaml file", nil},
	{"illegal structure - xml", "<elem attr=val />", nil},
	{"illegal structure - ini", "key = value", nil},
	{"illegal structure - tab indentation", "key1:\n\t'a: value", nil},
	{"simple keys",
		`
key1: val1
key2: ""
key3: `,
		map[string]string{"key1": "val1", "key2": "", "key3": ""}},
	{"nesting keys",
		`
key1:
  a:
    a1: val1
    a2: val2
  b: val3
key2: val4`,
		map[string]string{"key1.a.a1": "val1", "key1.a.a2": "val2", "key1.b": "val3", "key2": "val4"}},
	{"special characters",
		`
s p a c e s: y e s
sla/sh: ye/s
d.o.t.s: y.e.s
sepa:rator: yes
multiline1:
  hello
  world!
multiline2: |
  hello
  world!`,
		map[string]string{
			"s p a c e s": "y e s",
			"sla/sh":      "ye/s",
			"d.o.t.s":     "y.e.s",
			"sepa:rator":  "yes",
			"multiline1":  "hello world!",
			"multiline2":  "hello\nworld!",
		}},
	{"yaml with CR/LF",
		"key1: val1\r\nkey2:\r\n  a: val2",
		map[string]string{"key1": "val1", "key2.a": "val2"}},
	{"quote signs",
		`
"quotes":
  'single': 'ignored'
  'double': "ignored"
`,
		map[string]string{"quotes.single": "ignored", "quotes.double": "ignored"}},
	{"arrays",
		`
arrInLine: [a,b,c]
arr1:
  - 100
  - 200
arr2:
  - k1: v1
    k2: v2
  - k3: v3
  - k4:
      k5: v5
  - v6
`,
		map[string]string{
			"arrInLine[0]":  "a",
			"arrInLine[1]":  "b",
			"arrInLine[2]":  "c",
			"arr1[0]":       "100",
			"arr1[1]":       "200",
			"arr2[0].k1":    "v1",
			"arr2[0].k2":    "v2",
			"arr2[1].k3":    "v3",
			"arr2[2].k4.k5": "v5",
			"arr2[3]":       "v6",
		}},
}

var yamlTransformer = NewTransformer()

func TestTransform(t *testing.T) {
	tests.TestTransform(t, yamlTransformer, testCases)
}
