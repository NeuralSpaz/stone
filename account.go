package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	jose "gopkg.in/square/go-jose.v2"
)

func (c *Client) recoverAccountWithKey() error {

	ctx := context.Background()
	type Payload struct {
		OnlyReturnExisting bool `json:"onlyReturnExisting,omitempty"`
	}

	var newAccount Payload

	newAccount.OnlyReturnExisting = true

	reqBodyStr, err := json.Marshal(&newAccount)
	if err != nil {
		return err
	}

	var signedBody *jose.JSONWebSignature

	signedBody, err = c.signEmbedded(reqBodyStr, c.directory.NewAccount)

	if err != nil {
		return err
	}

	bodyBuf := bytes.NewBuffer([]byte(signedBody.FullSerialize()))

	// sr := strings.NewReader(string(reqBodyStr))
	resp, err := c.post(ctx, c.directory.NewAccount, "application/jose+json", bodyBuf)
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
			return c.recoverAccountWithKey()
		}
		if strings.Contains(jsonerr.Detail, "unable to find existing account") {
			return c.createNewAccount(ctx)
		}
	}

	c.acctID = resp.Header.Get("Location")
	// fmt.Printf("%+#v\n", resp.Body.Read())
	return nil
}
func (c *Client) getAccount() error {
	fmt.Println(c.acctID)
	ctx := context.Background()
	type Payload struct{}

	var empty Payload

	reqBodyStr, err := json.Marshal(&empty)
	if err != nil {
		return err
	}

	var signedBody *jose.JSONWebSignature

	signedBody, err = c.signEmbedded(reqBodyStr, c.acctID)

	if err != nil {
		return err
	}

	bodyBuf := bytes.NewBuffer([]byte(signedBody.FullSerialize()))

	// sr := strings.NewReader(string(reqBodyStr))
	resp, err := c.post(ctx, c.acctID, "application/jose+json", bodyBuf)
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
			return c.getAccount()
		}
	}

	fmt.Println("Here is the Header ", resp.Header)
	bodyBytes, _ := ioutil.ReadAll(resp.Body)
	bodyString := string(bodyBytes)
	fmt.Println(bodyString)

	var account Account
	if err := json.NewDecoder(resp.Body).Decode(&account); err != nil {
		if resp.StatusCode == http.StatusOK {

		}
	}
	c.acc = account

	return nil
}

func (c *Client) getAuthorisation(o Order) (Authorization, error) {
	ctx := context.Background()
	resp, err := c.get(ctx, o.Authorizations[0])
	if err != nil {
		return Authorization{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Authorization{}, fmt.Errorf("opps")
	}
	c.addNonce(&resp.Header)

	var auth Authorization
	if err := json.NewDecoder(resp.Body).Decode(&auth); err != nil {
		return Authorization{}, err
	}
	// logrus.Debugf("%+#v", auth)
	// fmt.Println(auth)
	c.Authz = append(c.Authz, auth)
	return auth, nil
}

func (c *Client) getCertificate()    {}
func (c *Client) renewCeritficate()  {}
func (c *Client) updateAccount()     {}
func (c *Client) keyRollOver()       {}
func (c *Client) deactivateAccount() {}
func (c *Client) finalize()          {}
