package main

import "github.com/k0kubun/pp"

type Directory struct {
	Meta struct {
		TermsOfService          string   `json:"termsOfService"`
		Website                 string   `json:"website"`
		CaaIdentities           []string `json:"caaIdentities"`
		ExternalAccountRequired bool     `json:"externalAccountRequired"`
	} `json:"meta"`
	NewAccount string `json:"newAccount"`
	NewNonce   string `json:"newNonce"`
	NewOrder   string `json:"newOrder"`
	RevokeCert string `json:"revokeCert"`
	NewAuthz   string `json:"newAuthz"`
	KeyChange  string `json:"keyChange"`
}

type AcmeErrors struct {
	Type        string `json:"type"`
	Detail      string `json:"detail"`
	Subproblems []struct {
		Type       string `json:"type"`
		Detail     string `json:"detail"`
		Identifier struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"identifier"`
	} `json:"subproblems"`
}

type Account struct {
	Status             string   `json:"status"`
	Contact            []string `json:"contact"`
	ToSAgreed          bool     `json:"termsOfServiceAgreed"`
	Orders             string   `json:"orders,omitempty"`
	OnlyReturnExisting bool     `json:"onlyReturnExisting"`
}

type OrdersList struct {
	Orders []string `json:"orders"`
}

type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type Order struct {
	Status         string       `json:"status"`
	Expires        string       `json:"expires"`
	Identifiers    []Identifier `json:"identifiers,omitempty"`
	Finalize       string       `json:"finalize"`
	NotBefore      string       `json:"notBefore,omitempty"`
	NotAfter       string       `json:"notAfter,omitempty"`
	Authorizations []string     `json:"authorizations"`
	Certificate    string       `json:"certificate,omitempty"`
}

type Authorization struct {
	Status     string      `json:"status"`
	Identifier Identifier  `json:"identifier"`
	Challenges []Challenge `json:"challenges"`
	Expires    string      `json:"expires"`
	// Wildcard is a Let's Encrypt specific Authorization field that indicates the
	// authorization was created as a result of an order containing a name with
	// a `*.`wildcard prefix. This will help convey to users that an
	// Authorization with the identifier `example.com` and one DNS-01 challenge
	// corresponds to a name `*.example.com` from an associated order.
	Wildcard bool `json:"wildcard,omitempty"`
}

func (a Authorization) String() string {
	return pp.Sprint(a)
}

type ProtectedPost struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// A Challenge is used to validate an Authorization
type Challenge struct {
	Type   string `json:"type"`
	URL    string `json:"url"`
	Token  string `json:"token"`
	Status string `json:"status"`
	// Validated        string          `json:"validated,omitempty"`
	// KeyAuthorization string          `json:"keyAuthorization,omitempty"`
	// Error            *ProblemDetails `json:"error,omitempty"`
}

type DNS01ChallengeResponcse struct {
	Protected struct {
		Alg   string `json:"alg"`
		Kid   string `json:"kid"`
		Nonce string `json:"nonce"`
		URL   string `json:"url"`
	} `json:"protected"`
	Payload struct {
		KeyAuthorization string `json:"keyAuthorization"`
	} `json:"payload"`
	Signature string `json:"signature"`
}

const (
	StatusPending    = "pending"
	StatusInvalid    = "invalid"
	StatusValid      = "valid"
	StatusProcessing = "processing"

	IdentifierDNS = "dns"

	ChallengeHTTP01   = "http-01"
	ChallengeTLSSNI02 = "tls-sni-02"
	ChallengeDNS01    = "dns-01"

	HTTP01BaseURL = ".well-known/acme-challenge/"
)

// Account Creation
// type AutoGenerated struct {
// 	Protected struct {
// 		Alg string `json:"alg"`
// 		Jwk struct {
// 		} `json:"jwk"`
// 		Nonce string `json:"nonce"`
// 		URL   string `json:"url"`
// 	} `json:"protected"`
// 	Payload struct {
// 		TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed"`
// 		Contact              []string `json:"contact"`
// 	} `json:"payload"`
// 	Signature string `json:"signature"`
// }

// type AutoGenerated struct {
// 	Status               string   `json:"status"`
// 	Contact              []string `json:"contact"`
// 	TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed"`
// 	Orders               string   `json:"orders"`
// }
