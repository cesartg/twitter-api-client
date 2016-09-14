//Package twitterapiclient provides a function to send an authorized request to the Twitter API
package twitterapiclient

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cesartg/gutil/collections"
	"github.com/cesartg/gutil/cryptography"
	"github.com/cesartg/gutil/http"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"os"
)

const (
	credentialsFile = "config.json"
	oauthVersion    = "1.0"
	signatureMethod = "HMAC-SHA1"
)

type twitterCredentials struct {
	AccessToken       string
	AccessTokenSecret string
	ConsumerKey       string
	ConsumerSecret    string
}

var credentials twitterCredentials

func init() {
	unmarshalCredentialsFromFile()
}

func unmarshalCredentialsFromFile() {
	byteArray := readCredentialsFile()
	err := json.Unmarshal(byteArray, &credentials)
	if err != nil {
		log.Panicf("Panicking. Error during twitter unmarshiling credentials from file %s. Error detail: %s",
			credentialsFile, err)
	}
}

func readCredentialsFile() []byte {
	log.Print("INFO: Reading twitter credentials from file " + credentialsFile)
	pwd, _ := os.Getwd()
	byteArray, err := ioutil.ReadFile(pwd + "/" + credentialsFile)
	if err != nil {
		log.Panicf("Panicking. Error during reading twitter credentials from file %s. Error detail: %s",
			credentialsFile, err)
	}
	return byteArray
}

// SendTwitterAPIRequest sends an authorized request to the twitter API to given url and using the given http method.
// Returns the response as string
// This use the client credentials specified in config.json
func SendTwitterAPIRequest(absoluteURL string, httpMethod string) ([]byte, error) {
	err := verifyCredentialsAreNotEmpty()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(httpMethod, absoluteURL, nil)
	if err != nil {
		return nil, err
	}
	authorizationHeaderValue := buildAuthorizationHeaderValue(httpMethod, req.URL)
	req.Header.Add("Authorization", authorizationHeaderValue)
	response, err := httputil.DoRequest(req)
	if err != nil {
		return nil, err
	}
	return response, err
}

func verifyCredentialsAreNotEmpty() error {
	if len(credentials.AccessTokenSecret) == 0 || len(credentials.AccessToken) == 0 ||
		len(credentials.ConsumerKey) == 0 || len(credentials.ConsumerSecret) == 0 {
		return errors.New("Access token, consumer key and/or other credentials are empty")
	}
	return nil
}

func buildAuthorizationHeaderValue(httpMethod string, requestURL *url.URL) string {
	var buffer bytes.Buffer
	buffer.WriteString("OAuth ")
	oAuthParams := generateOAuthParams(httpMethod, requestURL)
	sortedKeys := collections.SortKeys(oAuthParams)
	for i, k := range sortedKeys {
		if i != 0 {
			buffer.WriteString(", ")
		}
		buffer.WriteString(k)
		buffer.WriteString("=\"")
		buffer.WriteString(url.QueryEscape(oAuthParams[k]))
		buffer.WriteString("\"")
	}
	authorizationHeaderValue := buffer.String()
	log.Print("INFO: Authorization header value: " + authorizationHeaderValue)
	return authorizationHeaderValue
}

func generateOAuthParams(httpMethod string, requestURL *url.URL) map[string]string {
	log.Print("INFO: Generating OAuth Params")
	oAuthParams := map[string]string{
		"oauth_consumer_key":     credentials.ConsumerKey,
		"oauth_nonce":            cryptography.GenerateNonceBase32(),
		"oauth_signature_method": signatureMethod,
		"oauth_timestamp":        strconv.FormatInt(time.Now().Unix(), 10),
		"oauth_token":            credentials.AccessToken,
		"oauth_version":          oauthVersion,
	}
	signature := generateOAuthSignature(oAuthParams, httpMethod, requestURL)
	oAuthParams["oauth_signature"] = signature
	return oAuthParams
}

func generateOAuthSignature(oauthParams map[string]string, httpMethod string, requestURL *url.URL) string {
	log.Print("INFO: Generating Oauth Signature")
	params := make(map[string]string)
	for k, v := range oauthParams {
		params[k] = v
	}
	for k := range requestURL.Query() {
		params[k] = requestURL.Query().Get(k)
	}
	parameterString := buildParameterString(params)
	signingKey := []byte(credentials.ConsumerSecret + "&" + credentials.AccessTokenSecret)
	mac := hmac.New(sha1.New, signingKey)
	baseURL := fmt.Sprintf("%s://%s%s", requestURL.Scheme, requestURL.Host, requestURL.EscapedPath())
	io.WriteString(mac, strings.ToUpper(httpMethod)+"&"+url.QueryEscape(baseURL)+"&"+parameterString)
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func buildParameterString(params map[string]string) string {
	sortedKeys := collections.SortKeys(params)
	var buffer bytes.Buffer
	for i, k := range sortedKeys {
		if i != 0 {
			buffer.WriteByte('&')
		}
		buffer.WriteString(k)
		buffer.WriteByte('=')
		buffer.WriteString(params[k])

	}
	unencodedParameterString := buffer.String()
	log.Println(unencodedParameterString)
	return encodedQueryString(unencodedParameterString)
}

func encodedQueryString(query string) string {
	query = strings.Replace(query, "=", "%3D", -1)
	query = strings.Replace(query, "&", "%26", -1)
	query = strings.Replace(query, " ", "%2520", -1)
	query = strings.Replace(query, "+", "%252B", -1)
	query = strings.Replace(query, ",", "%252C", -1)
	query = strings.Replace(query, "!", "%2521", -1)
	return query
}
