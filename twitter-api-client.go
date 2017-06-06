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
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	credentialsFile = "config.json"
	oauthVersion = "1.0"
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
	byteArray, err := ioutil.ReadFile(credentialsFile)
	if err != nil {
		log.Panicf("Panicking. Error during reading twitter credentials from file %s. Error detail: %s",
			credentialsFile, err)
	}
	return byteArray
}

// Sends an authorized request to the twitter API to given url and using the given http method.
// Returns the response as string
// This use the client credentials specified in config.json
func SendTwitterApiRequest(absoluteUrl string, httpMethod string) ([]byte, error) {
	err := verifyCredentialsAreNotEmpty()
	if (err != nil) {
		return nil, err
	}
	req, err := http.NewRequest(httpMethod, absoluteUrl, nil)
	if (err != nil) {
		return nil, err
	}
	authorizationHeaderValue := buildAuthorizationHeaderValue(httpMethod, req.URL)
	req.Header.Add("Authorization", authorizationHeaderValue)
	response, err := doRequest(req)
	if err != nil {
		return nil, err
	}
	return response, err
}

func verifyCredentialsAreNotEmpty() error {
	if len(credentials.AccessTokenSecret) == 0 || len(credentials.AccessToken) == 0 ||
		len(credentials.ConsumerKey) == 0 || len(credentials.ConsumerSecret) == 0 {
		return errors.New("Access token, consumer key and/or other credentials are empty");
	}
	return nil
}

func buildAuthorizationHeaderValue(httpMethod string, requestUrl *url.URL) string {
	var buffer bytes.Buffer
	buffer.WriteString("OAuth ")
	oAuthParams := generateOAuthParams(httpMethod, requestUrl)
	sortedKeys := sortKeys(oAuthParams)
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

func sortKeys(unsortedMap map[string]string) []string {
	keys := make([]string, len(unsortedMap))
	i := 0
	for k := range unsortedMap {
		keys[i] = k
		i++
	}
	sort.Strings(keys)
	return keys
}

func doRequest (request *http.Request) ([]byte, error) {
	client := &http.Client{}
	url := request.URL.String()
	log.Printf("INFO: Doing request to %s", url)
	res, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	byteArray, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	return byteArray, err
}

func generateOAuthParams(httpMethod string, requestUrl *url.URL) map[string]string {
	log.Print("INFO: Generating OAuth Params")
	oAuthParams := map[string]string{
		"oauth_consumer_key" : credentials.ConsumerKey,
		"oauth_nonce" : generateNonceBase32(),
		"oauth_signature_method" : signatureMethod,
		"oauth_timestamp" : strconv.FormatInt(time.Now().Unix(), 10),
		"oauth_token" : credentials.AccessToken,
		"oauth_version" : oauthVersion,
	}
	signature := generateOAuthSignature(oAuthParams, httpMethod, requestUrl)
	oAuthParams["oauth_signature"] = signature
	return oAuthParams
}

func generateNonceBase32() string {
	now := time.Now().Unix()
	return strconv.FormatInt(now, 32) + strconv.FormatInt(rand.Int63(), 32)
}

func generateOAuthSignature(oauthParams map[string]string, httpMethod string, requestUrl *url.URL) string {
	log.Print("INFO: Generating Oauth Signature")
	params := make(map[string]string)
	for k, v := range oauthParams {
		params[k] = v
	}
	for k := range requestUrl.Query() {
		params[k] = requestUrl.Query().Get(k)
	}
	parameterString := buildParameterString(params)
	signingKey := []byte(credentials.ConsumerSecret + "&" + credentials.AccessTokenSecret)
	mac := hmac.New(sha1.New, signingKey)
	baseUrl := fmt.Sprintf("%s://%s%s", requestUrl.Scheme, requestUrl.Host, requestUrl.EscapedPath())
	io.WriteString(mac, strings.ToUpper(httpMethod) + "&" + url.QueryEscape(baseUrl) + "&" + parameterString)
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func buildParameterString(params map[string]string) string {
	sortedKeys := sortKeys(params)
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
