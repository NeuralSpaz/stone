package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/k0kubun/pp"
	"github.com/sirupsen/logrus"
	jose "gopkg.in/square/go-jose.v2"
)

// AcmeDiscoveryURL is the endpoint discovery url for acme v2
const AcmeDiscoveryURL = "https://127.0.0.1:14000/dir"

type Client struct {
	// key crypto.Signer
	// privKey      *rsa.PrivateKey
	privKey      jose.SigningKey
	HTTPClient   *http.Client
	DirectoryURL string
	directory    Directory
	nonces       []string
	acctID       string
	acc          Account
	Orders       []Order
	OrdersList   []string
	Authz        []Authorization
	// account      string
}

func (c Client) String() string {
	return pp.Sprint(c)
}

// func (c Client) String() string {
// 	var str string
// 	// str += fmt.Sprintf("Key:%v\n", c.privKey.Key)
// 	str += fmt.Sprintf("Account:%v\n", c.acctID)
// 	str += fmt.Sprintf("AccountDetails :%+#v\n", c.acc)
// 	for _, v := range c.OrdersList {
// 		str += fmt.Sprintf("Order: %v\n", v)
// 	}
// 	for _, v := range c.Orders {
// 		str += fmt.Sprintf("Orders: %+#v\n", v)
// 	}
// 	return str
// }

func main() {
	fmt.Println("Starting Stone")
	// logrus.WithFields(logrus.Fields{"String": "hi", "Integer": 2, "Boolean": false}).Debug("Check this out! Awesome, right?")

	c := NewClient()
	ctx := context.Background()

	// cancel()

	if _, err := c.Discover(ctx); err != nil {
		log.Println(err)
	}
	// if err := c.getNewNonce(ctx); err != nil {
	// 	log.Println(err)
	// }

	// if err := c.createNewAccount(ctx); err != nil {
	// 	log.Println(err)
	// }
	if err := c.recoverAccountWithKey(); err != nil {
		log.Fatalln(err)
	}
	if err := c.getAccount(); err != nil {
		log.Fatalln(err)
	}

	if err := c.createOrder(ctx); err != nil {
		log.Println(err)
	}
	if err := c.getOrders(ctx); err != nil {
		log.Println(err)
	}
	var authz []Authorization
	for _, order := range c.Orders {
		auth, err := c.getAuthorisation(order)
		if err != nil {
			log.Println(err)
		}
		authz = append(authz, auth)
	}
	// fmt.Printf("%#+v\n", authz)
	fmt.Println(c)
	// fmt.Printf("\n%#+v\n", authz)
}

func NewClient() Client {
	data, err := ioutil.ReadFile("private.pem")
	if err != nil {
		log.Fatalln(err)
	}

	// var pemkey = &pem.Block{
	// 	Type:  "RSA PRIVATE KEY",
	// 	Bytes: x509.MarshalPKCS1PrivateKey(privatekey)}

	block, _ := pem.Decode(data)

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	// privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	// if err != nil {
	// 	fmt.Println(err)
	// }

	pemfile, err := os.Create("private2.pem")

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// http://golang.org/pkg/encoding/pem/#Block
	var pemkey = &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv)}

	err = pem.Encode(pemfile, pemkey)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	pemfile.Close()

	return Client{
		// key:          pr
		privKey: jose.SigningKey{
			Key:       priv,
			Algorithm: jose.RS256,
		},
		DirectoryURL: AcmeDiscoveryURL,
		HTTPClient:   &http.Client{},
	}
}

func (c *Client) createNewAccount(ctx context.Context) error {

	type Payload struct {
		TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed,omitempty"`
		Contact              []string `json:"contact,omitempty"`
		OnlyReturnExisting   bool     `json:"onlyReturnExisting,omitempty"`
	}

	var newAccount Payload

	newAccount.Contact = []string{"mailto:test@test.com"}
	newAccount.TermsOfServiceAgreed = true

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
	}

	c.acctID = resp.Header.Get("Location")
	// fmt.Printf("%+#v\n", resp.Body.Read())
	return nil
}

func (c *Client) Discover(ctx context.Context) (Directory, error) {
	ctx, _ = context.WithTimeout(ctx, time.Second*10)
	ctx = context.WithValue(ctx, "caller", "discover")
	resp, err := c.get(ctx, c.DirectoryURL)
	if err != nil {
		return Directory{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Directory{}, fmt.Errorf("opps")
	}
	c.addNonce(&resp.Header)

	var d Directory
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return Directory{}, err
	}
	c.directory = d
	return d, nil
}

func (c *Client) get(ctx context.Context, urlStr string) (*http.Response, error) {
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return nil, err
	}
	ctx = context.WithValue(ctx, "url", urlStr)
	return c.do(ctx, req)
}

func (c *Client) head(ctx context.Context, urlStr string) (*http.Response, error) {
	req, err := http.NewRequest("HEAD", urlStr, nil)
	if err != nil {
		return nil, err
	}
	ctx = context.WithValue(ctx, "url", urlStr)
	return c.do(ctx, req)
}

func (c *Client) post(ctx context.Context, urlStr, contentType string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest("POST", urlStr, body)
	if err != nil {
		return nil, err
	}
	ctx = context.WithValue(ctx, "url", urlStr)
	req.Header.Set("Content-Type", contentType)
	return c.do(ctx, req)
}

func (c *Client) do(ctx context.Context, req *http.Request) (*http.Response, error) {
	res, err := c.HTTPClient.Do(req.WithContext(ctx))
	if err != nil {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("%v, while doing %v got %v", ctx.Value("caller"), ctx.Value("url"), ctx.Err())
		default:
			return nil, err
		}
	}
	return res, nil
}

func (c *Client) addNonce(head *http.Header) {
	nonce := head.Get("Replay-Nonce")
	if nonce != "" {
		c.nonces = append(c.nonces, nonce)
	}
}

func (c *Client) Nonce() (string, error) {
	ctx := context.Background()
	resp, err := c.head(ctx, c.directory.NewNonce)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode > 299 {
		return "", fmt.Errorf("expected http status code %v, but got %v", http.StatusNoContent, resp.StatusCode)
	}
	nonce := resp.Header.Get("Replay-Nonce")
	if nonce == "" {
		return "", fmt.Errorf("expected nonce in resp but got nothing")
	}

	return nonce, nil
}

// func (c *Client) useNonce() string {
// 	// a = append(a[:i], a[i+1:]...)
// 	var nonce string
// 	if len(c.nonces) == 0 {
// 		ctx := context.Background()
// 		nonce, err := c.getNewNonce(ctx)
// 	}
// 	nonce := c.nonces[0]
// 	c.nonces = append(c.nonces, c.nonces[1:]...)
// 	return nonce
// }

func (c *Client) getNewNonce(ctx context.Context) (string, error) {
	resp, err := c.head(ctx, c.directory.NewNonce)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode > 299 {
		return "", fmt.Errorf("expected http status code %v, but got %v", http.StatusNoContent, resp.StatusCode)
	}
	nonce := resp.Header.Get("Replay-Nonce")
	if nonce == "" {
		return "", fmt.Errorf("expected nonce in resp but got nothing")
	}

	return nonce, nil
}

// func (d Directory) createNewAccount() {

// 	type NewAccount struct {
// 		Alg string `json:"alg"`
// 		Jwk struct {
// 		} `json:"jwk"`
// 		Nonce                string   `json:"nonce"`
// 		URL                  string   `json:"url"`
// 		TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed"`
// 		Contact              []string `json:"contact"`
// 		Signature            string   `json:"signature"`
// 	}

// 	var a NewAccount
// 	a.Contact = []string{"test@example.com"}
// 	// a.Nonce = nonce
// 	newNone, err := d.getNewNonce()
// 	if err != nil {
// 		fmt.Println(err)
// 	}
// 	fmt.Println(newNone)
// }

// func fetchJson(ctx context.Context, url string, v interface{}) (string, error) {
// 	resp, err := httpGet(ctx, url)
// 	if err != nil {
// 		ctx.Err()
// 		return "", err
// 	}
// 	defer resp.Body.Close()
// 	fmt.Printf("%+#v", resp)
// 	return resp.Header.Get("Replay-Nonce"), json.NewDecoder(resp.Body).Decode(v)
// }

// func httpGet(ctx context.Context, url string) (*http.Response, error) {
// 	req, err := http.NewRequest("GET", url, nil)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to get %q: %v", url, err)
// 	}
// 	var netClient = &http.Client{
// 		Timeout: time.Second * 10,
// 	}
// 	return netClient.Do(req)
// }

// func base64url(v interface{}) (string, error) {
// 	return "", nil
// }

func init() {
	logrus.SetFormatter(&logrus.TextFormatter{})
	logrus.SetOutput(os.Stderr)
	logrus.SetLevel(logrus.DebugLevel)
}
