package initransformer

import (
	"testing"

	"github.com/DefangLabs/secret-detector/pkg/transformers/tests"
)

var testCases = []tests.TestCase{
	{"empty input", "", nil},
	{"illegal structure", "this is not an ini file", nil},
	{"keys in default section",
		`
key1=value1
key2 = value2
key3: value3`,
		map[string]string{"key1": "value1", "key2": "value2", "key3": "value3"}},
	{"keys in a section",
		`
[section1]
key1=value1
key2 = value2
key3: value3`,
		map[string]string{"section1.key1": "value1", "section1.key2": "value2", "section1.key3": "value3"}},
	{"keys with different types",
		`
[empty values]
key1=
key2 =
key3:

[numbers]
int1 = 1
int2=-2
float1: 1.234
float2 = 2.30

[bool]
bool0: false
bool1 = true`,
		map[string]string{
			"empty values.key1": "",
			"empty values.key2": "",
			"empty values.key3": "",
			"numbers.int1":      "1",
			"numbers.int2":      "-2",
			"numbers.float1":    "1.234",
			"numbers.float2":    "2.30",
			"bool.bool0":        "false",
			"bool.bool1":        "true"}},
	{"keys with special characters",
		`
[ s p a c e s ]
are allowed = yes they are
[$pe.ci@l-#&*?]
can we? = yes, we can!
what/about\slashes=y/e\s
d.o.t.s = ...
["quotes"]
"double" = "ignored in key & value"
'single' = 'ignored for value'`,
		map[string]string{
			" s p a c e s .are allowed":        "yes they are",
			"$pe.ci@l-#&*?.can we?":            "yes, we can!",
			`$pe.ci@l-#&*?.what/about\slashes`: `y/e\s`,
			`$pe.ci@l-#&*?.d.o.t.s`:            `...`,
			`"quotes".double`:                  "ignored in key & value",
			`"quotes".'single'`:                "ignored for value"}},
	{"comments are ignored",
		`
# comment for section1
[section1]
key1=value1 ; inline comment for key1
; comment for section2
[section2]
key1=value1 # inline comment for key1
# comment for key2
key2=value2`,
		map[string]string{"section1.key1": "value1", "section2.key1": "value1", "section2.key2": "value2"}},
	{"nested keys and sections",
		`
[section1]
key1 =
  A = 1/1.A
  B = 1/1.B
[section1.sub1]
A = 1.1/A
B =
  a = 1.1/B.a
  b = 1.1/B.b
`,
		map[string]string{
			"section1.key1.A":   "1/1.A",
			"section1.key1.B":   "1/1.B",
			"section1.sub1.A":   "1.1/A",
			"section1.sub1.B.a": "1.1/B.a",
			"section1.sub1.B.b": "1.1/B.b",
		}},
	{"multiline values",
		`
multi = ln 1
  ln 2
  ln 3

[section]
multi =
  this is a
  long text
`,
		map[string]string{"multi": "ln 1\n  ln 2\n  ln 3", "section.multi": "\n  this is a\n  long text"}},
	{"ini with CR/LF", "key1=val1\r\nkey2:val2\n", map[string]string{"key1": "val1", "key2": "val2"}},
}

var iniTransformer = NewTransformer()

func TestTransform(t *testing.T) {
	tests.TestTransform(t, iniTransformer, testCases)
}
