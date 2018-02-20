package main

import (
	"fmt"

	jose "gopkg.in/square/go-jose.v2"
)

func (c *Client) signEmbedded(data []byte, url string) (*jose.JSONWebSignature, error) {
	signer, err := jose.NewSigner(c.privKey, &jose.SignerOptions{
		NonceSource: c,
		EmbedJWK:    true,
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": url,
		},
	})
	if err != nil {
		return nil, err
	}

	signed, err := signer.Sign(data)
	if err != nil {
		return nil, err
	}
	return signed, nil
}

func (c *Client) signKeyID(data []byte, url string) (*jose.JSONWebSignature, error) {
	jwk := &jose.JSONWebKey{
		Key:       c.privKey.Key,
		Algorithm: "RSA",
		KeyID:     c.acctID,
	}

	signerKey := jose.SigningKey{
		Key:       jwk,
		Algorithm: jose.RS256,
	}

	opts := &jose.SignerOptions{
		NonceSource: c,
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": url,
		},
	}

	signer, err := jose.NewSigner(signerKey, opts)
	if err != nil {
		fmt.Printf("Err making signer: %#v\n", err)
		return nil, err
	}
	signed, err := signer.Sign(data)
	if err != nil {
		fmt.Printf("Err using signer: %#v\n", err)
		return nil, err
	}
	return signed, nil
}
