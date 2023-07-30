// (c) Kamiar Bahri
package icannclient

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

// ICannAPI interface performs the basic funtions to interact
// with the ICANN's API.
type IIcannAPI interface {
	Authenticate()
	HTTPExec(method string, url string, hd http.Header, data []byte) HTTPResult
	GetCommonHeaders() http.Header
	Run()

	accessTokenExpired() bool
	waitForAuthAttemptTimeout()
	writeAccessTokenToDisk()
	getAccessTokenFromDisk()
}

// Run renews the access token every 23 hours
func (i *IcannAPI) Run() {

	for {
		acceessTokenExpired := i.accessTokenExpired()

		if acceessTokenExpired {
			i.Authenticated = false
			i.Authenticate()
		}

		if i.isDirty {
			// wait just over two minutes
			time.Sleep(126 * time.Second)

		} else {
			i.isDirty = true
		}
	}
}

// waitForAuthAttemptTimeout halts the system until
// it reaches an appropiate time to make another auth attmept.
// The limit is 8 attmept in 5 minutes per IP address.
func (i *IcannAPI) waitForAuthAttemptTimeout() {

	if mLastAuthenticationAttempt.Year() == 1 {
		// first time since the app has started
		return
	}

	// it's safer to wait the whole 2 minutes
	time.Sleep(2 * time.Minute)
}

// GetCommonHeaders gets the headers required by icann api.
func (i *IcannAPI) GetCommonHeaders() http.Header {
	hd := make(http.Header, 0)
	hd.Add("Accept", "application/json")
	hd.Add("Content-Type", "application/json")
	hd.Add("User-Agent", i.UserAgent)

	return hd
}

// accessTokenExpired returns true, if the issue-date of
// the access token a less than 24 hours.
func (i *IcannAPI) accessTokenExpired() bool {

	if i.AccessToken.Token == "" || i.AccessToken.DateTimeIssued.Year() < 2000 {
		i.getAccessTokenFromDisk()
	}

	// check for empty time
	if i.AccessToken.DateTimeIssued.Year() < time.Now().Year() {
		return true
	}

	return i.AccessToken.DateTimeIssued.Add(23 * time.Hour).Before(time.Now())
}

// writeAccessTokenToDisk transforms i.AccessToken into hex
// and saves it to disk (tokenFileName in i.AppDataDir directory).
func (i *IcannAPI) writeAccessTokenToDisk() {

	if !FileOrDirExists(i.AppDataDir) {
		log.Fatal("unable to access appdata path")
		return
	}

	tokenFilePath := fmt.Sprintf("%s/%s", i.AppDataDir, tokenFileName)
	b, _ := json.Marshal(i.AccessToken)
	b = []byte(hex.EncodeToString(b))
	os.WriteFile(tokenFilePath, b, os.ModePerm)
}

// getAccessTokenFromDisk reads the tokenFileName from i.AppDataDir
// (if exists) and transforms its content into i.AccessToken.
func (i *IcannAPI) getAccessTokenFromDisk() {

	tokenFilePath := fmt.Sprintf("%s/%s", i.AppDataDir, tokenFileName)
	if !FileOrDirExists(tokenFilePath) {
		return
	}
	b, _ := os.ReadFile(tokenFilePath)
	b, _ = hex.DecodeString(string(b))

	json.Unmarshal(b, &i.AccessToken)
}

// Authenticate calls the authenticate and retreives an
// access code, which can be used by the ICzdsAPI interface.
func (i *IcannAPI) Authenticate() {

	actExp := i.accessTokenExpired()

	if !actExp {
		// token still good? test the token
		// hd := i.GetCommonHeaders()
		// hd.Add("Authorization", fmt.Sprintf("Bearer %s", i.AccessToken.Token))
		// res := i.HTTPExec(GET, czdsAPIDownloadLinksURL, hd, nil)
		// if res.StatusCode == 200 {
		i.Authenticated = true
		// 	return
		// }
	}

	i.waitForAuthAttemptTimeout()

	data := []byte(fmt.Sprintf(`{"username":"%s", "password":"%s"}`, i.UserName, i.Password))
	hd := i.GetCommonHeaders()
	res := i.HTTPExec(POST, authenticateBaseURL, hd, data)
	mLastAuthenticationAttempt = time.Now()

	// too many authentication attempts from the same IP address
	if res.StatusCode == http.StatusTooManyRequests {
		// not much can be done until ~2 minutes has elapsed,
		i.Authenticated = false
		return

	} else if res.StatusCode == 0 {
		// status-code zero in this case does not necessarily mean
		// that the authentication was rejected; it would rather mean
		// the icann api could make sense of the information passed to
		// it (i.e. hearders were not read). So, display the message
		// and try again. This func will be called again in 2 minutes.
		i.Authenticated = false
		log.Println("authentication failed: status-code: 0; trying again in 2 min...")
		return
	}

	if res.StatusCode != http.StatusOK {
		// whether api site was unavailable or authenticaton failed, it's a
		// good idea to bail out.
		log.Fatal("authentication failed status-code:", res.StatusCode)
	}

	var autRes autResult
	err := json.Unmarshal(res.ResponseBody, &autRes)
	if err != nil {
		// don't bail out; just display the error.
		// as we could be in a middle of a long-running download
		fmt.Println("")
		log.Println(err)
		return
	}

	if autRes.Message == "Authentication Successful" {
		i.Authenticated = true
		i.AccessToken.Token = autRes.AccessToken
		i.AccessToken.DateTimeIssued = time.Now()
		i.AccessToken.DateTimeExpires = time.Now().Add(23 * time.Hour)

		i.writeAccessTokenToDisk()

	} else {
		// unlikely, but still account for this (status-cocde=200 and
		// success message missing)
		log.Fatal("authentication failed:", autRes.Message)
	}

	return
}

// HTTPExec is wrappter to make http calls.
func (i *IcannAPI) HTTPExec(method string, urlx string, hd http.Header, data []byte) HTTPResult {

	var res HTTPResult

	client := &http.Client{}
	req, _ := http.NewRequest(method, urlx, bytes.NewBuffer([]byte(data)))

	req.Header = hd

	resp, err := client.Do(req)
	if err != nil {
		res.Error = err
		return res
	}
	body, _ := io.ReadAll(resp.Body)
	req.Body.Close()
	resp.Body.Close()
	client.CloseIdleConnections()

	res.ResponseHeaders = resp.Header
	res.StatusCode = resp.StatusCode
	res.ResponseBody = body

	return res
}
