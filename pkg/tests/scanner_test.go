package tests

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DefangLabs/secret-detector/pkg/dataformat"
	"github.com/DefangLabs/secret-detector/pkg/detectors/artifactory"
	"github.com/DefangLabs/secret-detector/pkg/detectors/aws"
	"github.com/DefangLabs/secret-detector/pkg/detectors/azure"
	"github.com/DefangLabs/secret-detector/pkg/detectors/basicauth"
	"github.com/DefangLabs/secret-detector/pkg/detectors/bearerauth"
	"github.com/DefangLabs/secret-detector/pkg/detectors/generic"
	"github.com/DefangLabs/secret-detector/pkg/detectors/github"
	"github.com/DefangLabs/secret-detector/pkg/detectors/jwt"
	"github.com/DefangLabs/secret-detector/pkg/detectors/keyword"
	"github.com/DefangLabs/secret-detector/pkg/detectors/mailchimp"
	"github.com/DefangLabs/secret-detector/pkg/detectors/npm"
	"github.com/DefangLabs/secret-detector/pkg/detectors/privatekey"
	"github.com/DefangLabs/secret-detector/pkg/detectors/sendgrid"
	"github.com/DefangLabs/secret-detector/pkg/detectors/slack"
	"github.com/DefangLabs/secret-detector/pkg/detectors/square"
	"github.com/DefangLabs/secret-detector/pkg/detectors/stripe"
	"github.com/DefangLabs/secret-detector/pkg/detectors/twilio"
	"github.com/DefangLabs/secret-detector/pkg/scanner"
	"github.com/DefangLabs/secret-detector/pkg/secrets"
	"github.com/stretchr/testify/assert"
	"go.yaml.in/yaml/v3"
	"gopkg.in/ini.v1"
)

const (
	artifactoryKey  = "artifactory"
	awsClientIdKey  = "awsClientId"
	awsKey          = "awsKey"
	mwsKey          = "mws"
	azureKey        = "azure"
	basicAuthKey    = "basicAuth"
	bearerAuthKey   = "bearerAuth"
	entropyKey      = "high_entropy_str"
	urlPwdKey       = "url"
	githubKey       = "github"
	jwtKey          = "jwt"
	keywordKey      = "secretKeyword"
	mailchimpKey    = "mailchimp"
	npmKey          = "npm"
	pkKey           = "pk"
	sendgridKey     = "sendgrid"
	slackTokenKey   = "slack"
	slackWebhookKey = "slack_webhook"
	squareKey       = "square"
	stripeKey       = "stripe"
	twilioKey       = "twilio"
)

var (
	artifactoryType  = artifactory.NewDetector().SecretType()
	awsClientIdType  = aws.NewClientIdDetector().SecretType()
	awsSecretKeyType = aws.NewSecretKeyDetector().SecretType()
	awsMWSKeyType    = aws.NewMWSKeyDetector().SecretType()
	azureType        = azure.NewDetector().SecretType()
	basicAuthType    = basicauth.NewDetector().SecretType()
	bearerAuthType   = bearerauth.NewDetector().SecretType()
	entropyType      = generic.NewHighEntropyStringDetector().SecretType()
	urlPwdType       = generic.NewURLPasswordDetector().SecretType()
	githubType       = github.NewDetector().SecretType()
	jwtType          = jwt.NewDetector().SecretType()
	keywordType      = keyword.NewDetector().SecretType()
	mailchimpType    = mailchimp.NewDetector().SecretType()
	npmType          = npm.NewDetector().SecretType()
	privateKeyType   = privatekey.NewDetector().SecretType()
	sendgridType     = sendgrid.NewDetector().SecretType()
	slackType        = slack.NewDetector().SecretType()
	squareType       = square.NewDetector().SecretType()
	stripeType       = stripe.NewDetector().SecretType()
	twilioType       = twilio.NewDetector().SecretType()

	input = map[string]string{
		artifactoryKey:  `AKCabcXYZ1234`,
		awsClientIdKey:  `A3TX1234567890ABCDEF`,
		awsKey:          `aws"12345+67890/abcdefghijklm+NOPQRSTUVWXYZ+"`,
		mwsKey:          `amzn.mws.12345678-1234-1234-1234-123456789012`,
		azureKey:        `AccountKey=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890+/abcdefghijklmnopqrstuv==`,
		basicAuthKey:    `Basic ABCDEFGHIJ+KLMNOPQRST/UVWXYZ,abcdefghij_klmnopqrstuvwxyz-1234567890==`,
		bearerAuthKey:   `Bearer ABCDEFGHIJ+KLMNOPQRST/UVWXYZ,abcdefghij_klmnopq.rstuvwxyz-1234567890==`,
		entropyKey:      `dGhpcyBpcyBhIHRlc3QgZm9yIGhpZ2ggZW50cm9weSBiYXNlNjQgc2VjcmV0IGRldGVjdGlvbg`,
		urlPwdKey:       `smtp://user@example.com:p455w0rd@smtp.example.com:465/`,
		githubKey:       `ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890`,
		jwtKey:          `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`,
		keywordKey:      `1qaz!QAZ`,
		mailchimpKey:    `1234567890abcdef1234567890abcdef-us99`,
		npmKey:          `//registry.npmjs.org/:_authToken=0af23f36-c523-4c87-b543-18ff3ed79bce`,
		pkKey:           "-----BEGIN DSA PRIVATE KEY-----\nwxyz+ABC=\n-----END DSA PRIVATE KEY-----",
		sendgridKey:     `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`,
		slackTokenKey:   `xapp-1-QKDD2TWZ27V-0372407459206-989awefasdf98afaw8e9ruw98efuq9w8ef1nmqlr39098af98ankjnpq9a0kme09`,
		slackWebhookKey: `https://hooks.slack.com/services/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`,
		squareKey:       `sq0atp-12345\6789_abcde-VWXYZ`,
		stripeKey:       `sk_live_1234567890abcdefgHIJKLMN`,
		twilioKey:       `AC1234567890abcdef1234567890abcdef`,
	}

	expectedSecrets = []secrets.DetectedSecret{
		{Key: artifactoryKey, Type: artifactoryType, Value: input[artifactoryKey]},
		{Key: awsClientIdKey, Type: awsClientIdType, Value: input[awsClientIdKey]},
		{Key: awsKey, Type: awsSecretKeyType, Value: input[awsKey]},
		{Key: mwsKey, Type: awsMWSKeyType, Value: input[mwsKey]},
		{Key: azureKey, Type: azureType, Value: input[azureKey]},
		{Key: basicAuthKey, Type: basicAuthType, Value: input[basicAuthKey]},
		{Key: bearerAuthKey, Type: bearerAuthType, Value: input[bearerAuthKey]},
		{Key: entropyKey, Type: entropyType, Value: input[entropyKey]},
		{Key: urlPwdKey, Type: urlPwdType, Value: input[urlPwdKey]},
		{Key: githubKey, Type: githubType, Value: input[githubKey]},
		{Key: jwtKey, Type: jwtType, Value: input[jwtKey]},
		{Key: keywordKey, Type: keywordType, Value: input[keywordKey]},
		{Key: mailchimpKey, Type: mailchimpType, Value: input[mailchimpKey]},
		{Key: npmKey, Type: npmType, Value: input[npmKey]},
		{Key: pkKey, Type: privateKeyType, Value: input[pkKey]},
		{Key: sendgridKey, Type: sendgridType, Value: input[sendgridKey]},
		{Key: slackTokenKey, Type: slackType, Value: input[slackTokenKey]},
		{Key: slackWebhookKey, Type: slackType, Value: input[slackWebhookKey]},
		{Key: squareKey, Type: squareType, Value: input[squareKey]},
		{Key: stripeKey, Type: stripeType, Value: input[stripeKey]},
		{Key: twilioKey, Type: twilioType, Value: input[twilioKey]},
	}
)

func TestScanFile(t *testing.T) {
	config := scanner.NewConfigWithDefaults()
	config.DetectorConfigs[keyword.Name] = []string{"0"} // reduce the keyword value entropy to test only the suspicious keywords
	defaultScanner, _ := scanner.NewScannerFromConfig(config)

	t.Run("test ScanFile with a binary file", func(t *testing.T) {
		b := make([]byte, 1024)
		rand.Read(b)
		path := createTestFile(t, "dat", b)

		actualSecrets, err := defaultScanner.ScanFile(path)
		assert.Nil(t, actualSecrets)
		assert.EqualError(t, err, secrets.NewNotTextFileError(path).Error())
	})

	t.Run("test ScanFile with a large text file", func(t *testing.T) {
		length := scanner.DefaultThreshold + 1
		b := make([]byte, length)
		rand.Read(b)
		in := fmt.Sprintf("%x", b)[:length]
		path := createTestFile(t, "big", []byte(in))

		actualSecrets, err := defaultScanner.ScanFile(path)
		assert.NoError(t, err)
		if assert.Len(t, actualSecrets, 1) {
			assert.Equal(t, actualSecrets[0].Key, path)
			assert.Equal(t, actualSecrets[0].Type, scanner.SizeThresholdViolationType)
			assert.Equal(t, actualSecrets[0].Value, "9.54MB")
		}
	})

	t.Run("test ScanFile with a non existing file", func(t *testing.T) {
		b := make([]byte, 1024)
		rand.Read(b)
		path := "./file.not_exist"

		actualSecrets, err := defaultScanner.ScanFile(path)
		assert.Nil(t, actualSecrets)
		os.IsNotExist(err)
		assert.ErrorIs(t, err, os.ErrNotExist)
	})
}

func TestJSON(t *testing.T) {
	b, err := json.MarshalIndent(input, "", "  ")
	if err != nil {
		t.FailNow()
	}

	test(t, dataformat.JSON, string(b), expectedSecrets)
}

func TestYAML(t *testing.T) {
	b, err := yaml.Marshal(input)
	if err != nil {
		t.FailNow()
	}

	test(t, dataformat.YAML, string(b), expectedSecrets)
}

func TestXMLElement(t *testing.T) {
	sb := &strings.Builder{}
	encoder := xml.NewEncoder(sb)
	encoder.Indent("", "  ")
	root := xml.StartElement{Name: xml.Name{Local: "root"}}
	tokens := []xml.Token{root}
	for key, value := range input {
		tag := xml.StartElement{Name: xml.Name{Local: key}}
		tokens = append(tokens, tag, xml.CharData(value), xml.EndElement{Name: tag.Name})
	}
	tokens = append(tokens, xml.EndElement{Name: root.Name})
	for _, token := range tokens {
		if err := encoder.EncodeToken(token); err != nil {
			t.FailNow()
		}
	}
	if err := encoder.Flush(); err != nil {
		t.FailNow()
	}

	expected := make([]secrets.DetectedSecret, len(expectedSecrets))
	for i, secret := range expectedSecrets {
		expected[i] = secrets.DetectedSecret{
			Key:   fmt.Sprintf("%v.%v", root.Name.Local, secret.Key),
			Type:  secret.Type,
			Value: secret.Value,
		}
	}

	test(t, dataformat.XML, sb.String(), expected)
}

func TestXMLAttributes(t *testing.T) {
	sb := &strings.Builder{}
	encoder := xml.NewEncoder(sb)
	encoder.Indent("", "  ")
	root := xml.StartElement{Name: xml.Name{Local: "root"}}
	tokens := []xml.Token{root}
	for key, value := range input {
		tag := xml.StartElement{
			Name: xml.Name{Local: key},
			Attr: []xml.Attr{{
				Name:  xml.Name{Local: "attr"},
				Value: value,
			}},
		}
		tokens = append(tokens, tag, xml.EndElement{Name: tag.Name})
	}
	tokens = append(tokens, xml.EndElement{Name: root.Name})
	for _, token := range tokens {
		if err := encoder.EncodeToken(token); err != nil {
			t.FailNow()
		}
	}
	if err := encoder.Flush(); err != nil {
		t.FailNow()
	}

	expected := make([]secrets.DetectedSecret, len(expectedSecrets))
	for i, secret := range expectedSecrets {
		expected[i] = secrets.DetectedSecret{
			Key:   fmt.Sprintf("%v.%v[attr]", root.Name.Local, secret.Key),
			Type:  secret.Type,
			Value: secret.Value,
		}
	}

	test(t, dataformat.XML, sb.String(), expected)
}

func TestINI(t *testing.T) {
	sb := &strings.Builder{}
	cfg := ini.Empty()
	section := cfg.Section("")
	for key, value := range input {
		section.NewKey(key, value)
	}
	cfg.WriteTo(sb)

	test(t, dataformat.INI, sb.String(), expectedSecrets)
}

func TestJustValues(t *testing.T) {
	for _, secret := range expectedSecrets {
		if secret.Key == urlPwdKey {
			fmt.Print("url")
		}
		var in string
		expected := make([]secrets.DetectedSecret, 0)
		switch secret.Key {
		case keywordKey:
			in = fmt.Sprintf("%s=%s", secret.Key, input[secret.Key])
			expected = append(expected, secrets.DetectedSecret{Key: secret.Key, Type: secret.Type, Value: secret.Value})
		case pkKey:
			in = input[secret.Key]
			if i := strings.Index(secret.Value, "\n"); i != -1 { // in pk we identify the header as value
				secret.Value = secret.Value[:i]
			}
			expected = append(expected, secrets.DetectedSecret{Key: "", Type: secret.Type, Value: secret.Value})
		case azureKey:
			in = input[secret.Key]
			expected = append(expected, secrets.DetectedSecret{Key: "AccountKey", Type: secret.Type, Value: secret.Value[11:]})
		default:
			in = input[secret.Key]
			expected = append(expected, secrets.DetectedSecret{Key: "", Type: secret.Type, Value: secret.Value})
		}

		test(t, dataformat.DataFormat(secret.Key), in, expected)
	}
}

func test(t *testing.T, format dataformat.DataFormat, input string, expectedSecrets []secrets.DetectedSecret) {
	config := scanner.NewConfigWithDefaults()
	config.DetectorConfigs[keyword.Name] = []string{"0"}                          // reduce the keyword value entropy to test only the suspicious keywords
	config.DetectorConfigs[generic.HighEntropyStringDetectorName] = []string{"0"} // reduce the keyword value entropy to test only the suspicious keywords
	defaultScanner, _ := scanner.NewScannerFromConfig(config)
	t.Helper()

	t.Run(fmt.Sprintf("test Scan - %s", format), func(t *testing.T) {
		actualSecrets, err := defaultScanner.Scan(input)
		assertSecrets(t, expectedSecrets, actualSecrets, err)
	})

	t.Run(fmt.Sprintf("test ScanReader - %s", format), func(t *testing.T) {
		actualSecrets, err := defaultScanner.ScanReader(strings.NewReader(input))
		assertSecrets(t, expectedSecrets, actualSecrets, err)
	})

	t.Run(fmt.Sprintf("test ScanWithFormat - %s", format), func(t *testing.T) {
		actualSecrets, err := defaultScanner.ScanWithFormat(strings.NewReader(input), format)
		assertSecrets(t, expectedSecrets, actualSecrets, err)
	})

	t.Run(fmt.Sprintf("test ScanWithFormat with an unknown format - %s", format), func(t *testing.T) {
		actualSecrets, err := defaultScanner.ScanWithFormat(strings.NewReader(input), "unknown")
		assertSecrets(t, expectedSecrets, actualSecrets, err)
	})

	t.Run(fmt.Sprintf("test ScanFile - %s", format), func(t *testing.T) {
		path := createTestFile(t, string(format), []byte(input))
		actualSecrets, err := defaultScanner.ScanFile(path)
		assertSecrets(t, expectedSecrets, actualSecrets, err)
	})
}

func assertSecrets(t *testing.T, expectedSecrets, actualSecrets []secrets.DetectedSecret, err error) {
	assert.NoError(t, err)
	if !assert.Len(t, actualSecrets, len(expectedSecrets)) {
		t.FailNow()
	}

	actualMap := make(map[string]secrets.DetectedSecret, len(actualSecrets))
	for _, secret := range actualSecrets {
		actualMap[secret.Key] = secret
	}

	for _, expected := range expectedSecrets {
		secret, found := actualMap[expected.Key]
		if assert.True(t, found) {
			assert.Equal(t, expected.Key, secret.Key)
			assert.Equal(t, expected.Type, secret.Type)
			assert.Equal(t, expected.Value, secret.Value)
		}
	}
}

func createTestFile(t *testing.T, extension string, input []byte) string {
	t.Helper()

	wd, err := os.Getwd()
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	path := filepath.Join(wd, "test_files")
	if err = os.MkdirAll(path, os.ModePerm); !assert.NoError(t, err) {
		t.FailNow()
	}

	path = filepath.Join(path, fmt.Sprintf("test.%s", extension))
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	defer func() {
		assert.NoError(t, f.Close())
	}()
	if _, err = f.Write(input); !assert.NoError(t, err) {
		t.FailNow()
	}
	t.Cleanup(func() {
		if err := os.Remove(path); err != nil {
			t.Logf("failed to remove file '%v': %v", path, err)
		}
	})

	return path
}
