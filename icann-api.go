// (c) Kamiar Bahri
package icannclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
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
}

// Run renews the access token every 24 hours
func (i *IcannAPI) Run() {

	for {
		actExp := i.accessTokenExpired()

		if actExp {
			i.Authenticated = false
			i.Authenticate()
		}

		if i.isDirty {
			time.Sleep(120 * time.Second)
		} else {
			i.isDirty = true
		}
	}
}

// waitForAuthAttemptTimeout halts the system until
// it is approiate to make another auth attmept. The limit is
// 8 attmept in 5 minutes per IP address.
func (i *IcannAPI) waitForAuthAttemptTimeout() {
	if mLastAuthenticationAttempt.Year() == 1 {
		return
	}

	d := time.Since(mLastAuthenticationAttempt)
	minutes := int(d.Minutes())

	secToSleep := 120 - (minutes * 60)

	if secToSleep < 1 {
		return
	}

	// wait for auth attmept timeout
	for i := 0; i < secToSleep; i++ {
		time.Sleep(time.Second)
	}
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

	// check for empty time
	if i.AccessToken.DateTimeIssued.Year() < time.Now().Year() {
		return true
	}

	return i.AccessToken.DateTimeIssued.Add(24 * time.Hour).Before(time.Now())
}

// Authenticate calls the authenticate and retreives an
// access code, which can be used by the ICzdsAPI interface.
func (i *IcannAPI) Authenticate() {

	actExp := i.accessTokenExpired()

	if !actExp {
		// token still good
		return
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
	}

	var autRes autResult
	err := json.Unmarshal(res.ResponseBody, &autRes)
	if err != nil {
		log.Fatal(err)
		return
	}

	if res.StatusCode == http.StatusOK && autRes.Message == "Authentication Successful" {
		i.Authenticated = true
		i.AccessToken.Token = autRes.AccessToken

	} else {
		log.Fatal("authentication failed status-code:", res.StatusCode, autRes.Message)
	}

	return
}

// HTTPExec is wrapper to make http calls.
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
