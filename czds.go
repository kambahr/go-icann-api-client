// (c) Kamiar Bahri
package icannclient

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"quenubes/icann/lib/util"
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
	DownloadZoneFile(localFilePath string, downloadLink string, wg *sync.WaitGroup) (int, error)
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

	// tldUnq is an array to keep track items already downloaded.
	// This list avoid any originated duplicates (i.e. net,net,com)
	var tldUnq []interface{}

	// go through the loop from the bottom so that the latest
	// gets downloaded first.
	for i := (len(dlinks) - 1); i >= 0; i-- {

		// still check for authentication between downloads
		c.waitUntilAutenticated()

		link := dlinks[i]
		localFilePath := c.getDownloadLocalFilePath(link)

		if c.todayZoneFileExistsOnDisk(localFilePath) {
			continue
		}

		// Always get the latest (one download for each tld)
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
		statusCode, err := c.DownloadZoneFile(localFilePath, link, nil)
		if err != nil {
			fmt.Println(" c.DownloadZoneFile()=>", oneTLD, err)
			// remove from the downloaded-list (success list)
			tldUnq = util.RemoveFromArray(tldUnq, oneTLD)

			c.downloadZoneFilePostErr(localFilePath, link, oneTLD, statusCode, err)

			// // it's a good idea to halt the download a bit
			time.Sleep(time.Minute)
		}
	}

	// download loop is done. Now see if there are any failures
	c.downloadFailedTLDs()

	c.cleanup()

	c.keepIdlUntilNextInternval()

	goto lblAgain
}

// todayZoneFileExistsOnDisk determins if a zone file
// for the current session is present on disk; so that
// if this app is turned off/on, and a successfully downloaded
// zone file exists; it will not be re-downloaded.
func (c *CzdsAPI) todayZoneFileExistsOnDisk(fp string) bool {

	fileName := filepath.Base(fp)

	// com => ~ 5 GB
	// net => ~ 500 MB
	files, err := os.ReadDir(c.icann.AppDataDir)
	if err != nil {
		log.Fatal(err)
	}

	for i := 0; i < len(files); i++ {
		fn := files[i].Name()
		if fileName == fn {
			fi, _ := files[i].Info()
			if strings.Contains(fileName, "-com.zone.gz") {
				gb := fi.Size() / 1024 / 1024 / 1024
				if gb > 4 {
					return true
				}
			}
			if strings.Contains(fileName, "-net.zone.gz") {
				mb := fi.Size() / 1024 / 1024
				if mb > 490 {
					return true
				}
			}
		}
	}

	return false
}
func (c *CzdsAPI) cleanup() {

	// remove lingering partially downloaded files
	files, err := os.ReadDir(c.icann.AppDataDir)
	if err != nil {
		log.Fatal(err)
	}

	for i := 0; i < len(files); i++ {
		fn := files[i].Name()

		if strings.HasSuffix(fn, ".part") {
			fp := fmt.Sprintf("%s/%s", c.icann.AppDataDir, fn)
			os.Remove(fp)
		}
	}
}
func (c *CzdsAPI) downloadFailedTLDs() {
	if len(c.icann.failedDownloadQueue) == 0 {
		return
	}

	c.removeMaxedoutItemsFromFailedDownloadList()

	for i := 0; i < len(c.icann.failedDownloadQueue); i++ {
		statusCode, err := c.DownloadZoneFile(c.icann.failedDownloadQueue[i].LocalFilePath,
			c.icann.failedDownloadQueue[i].DownloadURL, nil)

		if err != nil {
			fmt.Println(" c.DownloadZoneFile()=>", c.icann.failedDownloadQueue[i].TLD, err)
			c.downloadZoneFilePostErr(c.icann.failedDownloadQueue[i].LocalFilePath,
				c.icann.failedDownloadQueue[i].DownloadURL, c.icann.failedDownloadQueue[i].TLD, statusCode, err)

			time.Sleep(time.Minute)
		}

		c.removeMaxedoutItemsFromFailedDownloadList()
		if len(c.icann.failedDownloadQueue) == 0 {
			break
		}
	}
}
func (c *CzdsAPI) removeItemFromItemArry(s []failedDownloadItem, i int) []failedDownloadItem {
	s[len(s)-1], s[i] = s[i], s[len(s)-1]
	return s[:len(s)-1]
}

func (c *CzdsAPI) removeMaxedoutItemsFromFailedDownloadList() {
lblAgain:
	for i := 0; i < len(c.icann.failedDownloadQueue); i++ {

		// if error is: "...connection reset by peer", it won't do any good to re-try
		// successively; hopfuly download for the next session will be successfull.
		if c.icann.failedDownloadQueue[i].AttempCount > 2 ||
			strings.Contains(c.icann.failedDownloadQueue[i].ErrTxt, "connection reset by peer") {

			c.icann.failedDownloadQueue = c.removeItemFromItemArry(c.icann.failedDownloadQueue, i)

			if len(c.icann.failedDownloadQueue) == 0 {
				return
			}

			goto lblAgain
		}

	}
}
func (c *CzdsAPI) downloadZoneFilePostErr(localFilePath string, link string, oneTLD string, statusCode int, err error) {
	if err == nil {
		return
	}

	for i := 0; i < len(c.icann.failedDownloadQueue); i++ {
		if c.icann.failedDownloadQueue[i].TLD == oneTLD {
			c.icann.failedDownloadQueue[i].AttempCount = c.icann.failedDownloadQueue[i].AttempCount + 1
			return
		}
	}

	var item = failedDownloadItem{
		TLD:             oneTLD,
		DateTimeAborted: time.Now(),
		LocalFilePath:   localFilePath,
		DownloadURL:     link,
		AttempCount:     c.getFailedAttempCount(oneTLD) + 1,
		StatusCode:      statusCode,
		ErrTxt:          err.Error()}

	c.icann.failedDownloadQueue = append(c.icann.failedDownloadQueue, item)
}

// getFailedAttempCount returns the attemp-count of an item
// in the failed-attmpe queue.
func (c *CzdsAPI) getFailedAttempCount(tld string) uint8 {

	var attpCnt uint8
	lenx := len(c.icann.failedDownloadQueue)

	if lenx == 0 {
		return attpCnt
	}

	for i := 0; i < lenx; i++ {
		if c.icann.failedDownloadQueue[i].TLD == tld {
			return c.icann.failedDownloadQueue[i].AttempCount
		}
	}

	return attpCnt
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
			time.Sleep(time.Second)

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
		msg := fmt.Sprintf("error %d - %v", res.StatusCode, string(res.ResponseBody))
		log.Fatal("getZoneFileStatus()=>", urlx, msg)
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
		msg := fmt.Sprintf("error %d - %v", res.StatusCode, string(res.ResponseBody))
		log.Fatal("getDownloadLinks()=>", msg)
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

// keepIdlUntilNextInternval waits for >24 hours to download a file again.
// According to ICANN terms callers must wait for at least
// 24 hours between downloads...
func (c *CzdsAPI) keepIdlUntilNextInternval() {
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
