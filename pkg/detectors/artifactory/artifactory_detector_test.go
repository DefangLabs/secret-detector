package artifactory

import (
	"testing"

	"github.com/DefangLabs/secret-detector/pkg/detectors/tests"
)

var testCases = []tests.TestCase{
	{"token - minimal length", "AKCabcXYZ1234", true},
	{"token - long", "AKCabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890", true},
	{"token - too short", "AKC123456789", false},
	{"token - illegal prefix", "NAKCabcXYZ1234", false},
	{"token - illegal lowercase prefix", "akcabcXYZ1234", false},
	{"token - illegal characters", "AKCabcXYZ1234=", false},

	// {"password - minimal length", "AP0abcXYZ12", true},
	// {"password - long", "APEabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890", true},
	// {"password - too short", "AP0abcXYZ1", false},
	// {"password - illegal AP prefix", "NAP0abcXYZ12", false},
	// {"password - illegal lowercase AP prefix", "ap0abcXYZ12", false},
	// {"password - illegal prefix character", "APGabcXYZ12", false},
	// {"password - illegal lowercase prefix character", "APeabcXYZ12", false},
	// {"password - illegal character", "AP0abcXYZ12+", false},

	{"empty input", "", false},
}

var artifactoryDetector = NewDetector()

func TestScan(t *testing.T) {
	tests.TestScan(t, artifactoryDetector, testCases)
}

func TestScanWithKey(t *testing.T) {
	tests.TestScanWithKey(t, artifactoryDetector, testCases)
}

func TestScanWithMultipleMatches(t *testing.T) {
	tests.TestScanWithMultipleMatches(t, artifactoryDetector, testCases)
}

func TestScanMap(t *testing.T) {
	tests.TestScanMap(t, artifactoryDetector, testCases)
}
