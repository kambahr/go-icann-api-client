// (c) Kamiar Bahri
package icannclient

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"runtime"
	"sync"
	"time"

	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

// Write keeps track of the number of bytes
// written + the elapsed time; and writes the status
// to the console.
func (wm *TeeWriter) Write(p []byte) (int, error) {

	// for formatting the downloaded bytes
	mp := message.NewPrinter(language.English)

	n := len(p)
	wm.TotalDownloaded += uint64(n)

	d := time.Since(wm.StartTime)

	fmt.Printf("\r\t%s %v mb elapsed: %v", wm.TLDType, mp.Sprintf("%d", wm.TotalDownloaded/1024), formatDuration(d))

	return n, nil
}

// DownloadZoneFile downloads a zone file from an assigned link.
func (c *CzdsAPI) DownloadZoneFile(localFilePath string, downloadLink string, wg *sync.WaitGroup) error {

	if wg != nil {
		defer wg.Done()
	}

	ConsoleClearLastLine()
	fmt.Println("download Link:", downloadLink)

	// download will be skipped, if the local file exists.
	// note: in case of partial download (i.e. computer shutdown
	// or network drop), the bad file has to be removed manually.
	// This is important to keep up with the once-in-24
	// hour download agreement.
	if FileOrDirExists(localFilePath) {
		errTxt := fmt.Sprintf("%s already exist", localFilePath)
		fmt.Println(errTxt)
		return errors.New(errTxt)
	}

	headers := c.icann.GetCommonHeaders()
	headers.Add("Authorization", fmt.Sprintf("Bearer %s", c.icann.AccessToken.Token))

	// see if there is enough disk-space before
	// downloading the file. In case there is not
	// enough, keep waiting
	fs := c.getZoneFileStatus(downloadLink)
	if runtime.GOOS == linux {
		fileSizeGig := float64(fs.FileLength) / 1024.0 / 1024.0 / 1024.0
		allowedGB := getMaxFreeDiskForZoneFile()
		for {
			ok := fileSizeGig < allowedGB
			if ok {
				break
			} else {
				fmt.Println("")
				log.Printf("\rnot enough disk-space, please, free some disk-space to continue")
				time.Sleep(time.Minute)
			}
		}
	}

	fileName := path.Base(localFilePath)
	txtToDisplay := fmt.Sprintf("downloading '%s' as '%s'", fs.OriginalFileName, fileName)

	ConsoleClearLastLine()
	log.Println(txtToDisplay)

	tmName := fmt.Sprintf("_%s.part", time.Now().String()[48:])
	tempFilePath := fmt.Sprintf("%s%s", localFilePath, tmName)

	if FileOrDirExists(tempFilePath) {
		os.Remove(tempFilePath)
	}

	ioOutput, err := os.Create(tempFilePath)
	if err != nil {
		return err
	}

	// Get the data (no timeout; the zone files are large)
	client := &http.Client{}
	req, _ := http.NewRequest(http.MethodGet, downloadLink, nil)
	req.Header = headers
	resp, err := client.Do(req)
	if err != nil {
		ioOutput.Close()
		return err
	}

	defer resp.Body.Close()

	// Initialize the tee-writer.
	teeWriter := &TeeWriter{File: ioOutput, TempFilePath: tempFilePath,
		FileName: fileName, TLDType: fs.TLDType, StartTime: time.Now()}

	if _, err = io.Copy(ioOutput, io.TeeReader(resp.Body, teeWriter)); err != nil {
		ioOutput.Close()
		return err
	}

	// Close the file, before renaming it.
	ioOutput.Close()

	if err = os.Rename(tempFilePath, localFilePath); err != nil {
		return err
	}

	fmt.Println("")

	return nil
}
