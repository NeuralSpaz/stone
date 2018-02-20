package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	jose "gopkg.in/square/go-jose.v2"
)

func (c *Client) createOrder(ctx context.Context) error {
	// log.WithFields(log.Fields{"fqdn": "*.example.com"}).Debug("Create New Cert Order")

	type Payload struct {
		Identifiers []Identifier `json:"identifiers,omitempty"`
		NotBefore   string       `json:"notBefore,omitempty"`
		NotAfter    string       `json:"notAfter,omitempty"`
		// KID         string       `json:"kid,omitempty"`
	}

	var domain Identifier
	domain.Type = "dns"
	domain.Value = "*.example.com"
	var newOrder Payload
	now := time.Now()
	newOrder.NotBefore = now.Format(time.RFC3339)
	newOrder.NotAfter = now.Add(time.Hour).Format(time.RFC3339)
	newOrder.Identifiers = append(newOrder.Identifiers, domain)

	// newOrder.KID = c.account
	// nonce, err := c.getNewNonce(ctx)
	// if err != nil {
	// 	return err
	// }
	// newAccount.Nonce = nonce
	// newAccount.Contact = []string{"mailto:test@test.com"}
	// newAccount.TermsOfServiceAgreed = true

	reqBodyStr, err := json.Marshal(&newOrder)
	if err != nil {
		return err
	}

	var signedBody *jose.JSONWebSignature
	// var err error

	signedBody, err = c.signKeyID(reqBodyStr, c.directory.NewOrder)

	if err != nil {
		return err
	}

	bodyBuf := bytes.NewBuffer([]byte(signedBody.FullSerialize()))
	// fmt.Println("BBbody: ", string(bodyBuf.Bytes()))

	// sr := strings.NewReader(string(reqBodyStr))
	resp, err := c.post(ctx, c.directory.NewOrder, "application/jose+json", bodyBuf)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// fmt.Printf("%+#v\n", resp.Header)
	c.addNonce(&resp.Header)
	// fmt.Println(resp.Header.Get("Content-Type"))
	if resp.Header.Get("Content-Type") == "application/problem+json; charset=utf-8" {
		var jsonerr AcmeErrors
		json.NewDecoder(resp.Body).Decode(&jsonerr)
		fmt.Printf("%+#v\n", jsonerr)
		if strings.Contains(jsonerr.Detail, "invalid anti-replay nonce") {
			return c.createOrder(ctx)
		}
	}

	c.OrdersList = append(c.OrdersList, resp.Header.Get("Location"))
	// c.account = resp.Header.Get("Location")
	// fmt.Printf("%+#v\n", resp.Body
	return nil
}

func (c *Client) getOrders(ctx context.Context) error {
	for _, v := range c.OrdersList {
		resp, err := c.get(ctx, v)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("opps")
		}
		c.addNonce(&resp.Header)

		var order Order
		if err := json.NewDecoder(resp.Body).Decode(&order); err != nil {
			return err
		}
		c.Orders = append(c.Orders, order)

	}
	return nil
}
