// (c) Kamiar Bahri
package icannclient

import (
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CzdsAPI implements the ICzdsAPI interface.
type CzdsAPI struct {
	icann *IcannAPI
}

// ICzdsAPI is the interface for CzdsAPI.
type ICzdsAPI interface {
	DownloadZoneFile(localFilePath string, downloadLink string, wg *sync.WaitGroup) error
	ICANN() *IcannAPI
	Run()
}

// Run will download the authorized zone files once every >24 hours.
func (c *CzdsAPI) Run() {

lblAgain:

	c.waitUntilAutenticated()

	dlinks := c.getDownloadLinks()
	if len(dlinks) == 0 {
		log.Fatal("unable to get download-links")
	}

	var tldUnq []interface{}

	// go through the loop from the bottom so that the latest
	// gets downloaded first.
	for i := (len(dlinks) - 1); i >= 0; i-- {
		link := dlinks[i]
		localFilePath := c.getDownloadLocalFilePath(link)

		// Alway get the latest (one download for each tld)
		v := strings.Split(link, "/")
		oneTLD := v[len(v)-1]

		alreadyDowloaded := itemExists(tldUnq, oneTLD)

		if alreadyDowloaded {
			continue
		}
		tldUnq = append(tldUnq, oneTLD)

		// wait for each download to finish
		// (one file at a time per ip addr; as it's not a good idea
		// to download files simultaneousely from the same ip addr!).
		c.DownloadZoneFile(localFilePath, link, nil)
	}

	c.keepIdlUntilNextInternval()

	goto lblAgain
}

// ICANN exposes the IcannAPI to outside callers (public).
func (c *CzdsAPI) ICANN() *IcannAPI {
	return c.icann
}

// waitUntilAutenticated halts execution until the
// icann session is autenticated.
func (c *CzdsAPI) waitUntilAutenticated() {
	for {
		authOK := c.icann.Authenticated

		if !authOK {
			time.Sleep(500 * time.Millisecond)

		} else {
			break
		}
	}
}

// getZoneFileStatus gets the status of the zone-file via
// an http call with a HEAD method. The Content-Disposition
// header will display the original filename and the Content-Length
// will show the size of the file. The following is exmaples of the
// headers:
//
//	Content-Disposition:[attachment;filename=com.txt.gz]
//	Content-Language:[en] Content-Length:[4979876869]
//
// To see all returned headers, see Result.ResponseHeaders.
func (c *CzdsAPI) getZoneFileStatus(urlx string) ZoneFileStatus {

	var r ZoneFileStatus

	fmt.Printf("\rgetting file-status...")

	hd := c.icann.GetCommonHeaders()
	hd.Add("Authorization", fmt.Sprintf("Bearer %s", c.icann.AccessToken.Token))

	res := c.icann.HTTPExec(HEAD, urlx, hd, nil)
	if res.StatusCode != 200 {
		log.Fatalf("\nerror %d - %v", res.StatusCode, string(res.ResponseBody))
	}

	sizeStr := fmt.Sprintf("%v", res.ResponseHeaders["Content-Length"])
	sizeStr = strings.ReplaceAll(sizeStr, "[", "")
	sizeStr = strings.ReplaceAll(sizeStr, "]", "")
	r.FileLength, _ = strconv.ParseUint(sizeStr, 0, 64)

	var fName string

	x := fmt.Sprintf("%v", res.ResponseHeaders["Content-Disposition"])

	fName = strings.Split(x, "=")[1]
	fName = strings.ReplaceAll(fName, "[", "")
	fName = strings.ReplaceAll(fName, "]", "")

	r.TLDType = strings.Split(fName, ".")[0]

	r.HTTPResult = res
	r.OriginalFileName = fName

	return r
}

// getDownloadLinks makes an http call to the czdsAPIDownloadLinksURL
// and receives the downloads for authrorized zone files.
func (c *CzdsAPI) getDownloadLinks() []string {

	var dlinks []string
	hd := c.icann.GetCommonHeaders()
	hd.Add("Authorization", fmt.Sprintf("Bearer %s", c.icann.AccessToken.Token))

	res := c.icann.HTTPExec(GET, czdsAPIDownloadLinksURL, hd, nil)
	if res.StatusCode != 200 {
		log.Fatalf("\nerror %d - %v", res.StatusCode, string(res.ResponseBody))
	}

	json.Unmarshal(res.ResponseBody, &dlinks)

	return dlinks
}

// getFileNameFromDownloadLink concats the appdata path to
// a file name created after today's date.
func (c *CzdsAPI) getFileNameFromDownloadLink(link string) string {

	v := strings.Split(link, "/")
	fName := v[len(v)-1]
	fName = fmt.Sprintf("%02d-%02d-%02d-%s", time.Now().Year(), time.Now().Month(), time.Now().Day(), fName)

	return fName
}

// getDownloadLocalFilePath gets the local file path that the
// downloaded bytes will be written to.
func (c *CzdsAPI) getDownloadLocalFilePath(link string) string {

	fName := c.getFileNameFromDownloadLink(link)

	localFilePath := fmt.Sprintf("%s/%s.gz", c.icann.AppDataDir, fName)

	return localFilePath
}

func (c *CzdsAPI) keepIdlUntilNextInternval() {
	// Need to wait for >24 hours to download a file again.
	// According to ICANN terms caller must wait for at least
	// 24 hours between downloads...
	nextTime := time.Now().Add(time.Duration(c.icann.HoursToWaitBetweenDownloads) * time.Hour)
	tCounter := c.icann.HoursToWaitBetweenDownloads * 60 * 60 // seconds

	fmt.Println("")

	for {
		if tCounter < 1 {
			break
		}

		t := time.Until(nextTime)
		d := formatDuration(t)
		fmt.Printf("\rdownload will resume in %s", d)

		time.Sleep(time.Second)

		nextTime = nextTime.Add(-1 * time.Second)
		tCounter--
	}
}
