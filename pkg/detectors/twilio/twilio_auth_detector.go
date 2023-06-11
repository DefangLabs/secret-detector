package twilio

import (
	"github.com/octarinesec/secret-detector/pkg/detectors/helpers"
	"github.com/octarinesec/secret-detector/pkg/secrets"
)

const (
	Name       = "twilio"
	secretType = "Twilio authentication"

	// see https://www.twilio.com/docs/glossary/what-is-a-sid
	accountSIDRegex = `AC[0-9a-fA-F]{32}`
	authTokenRegex  = `SK[0-9a-fA-F]{32}`
)

func init() {
	secrets.GetDetectorFactory().Register(Name, NewDetector)
}

type detector struct {
	secrets.Detector
}

func NewDetector(config []string) secrets.Detector {
	return &detector{
		Detector: helpers.NewRegexDetector(secretType, accountSIDRegex, authTokenRegex),
	}
}
