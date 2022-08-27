// (c) Kamiar Bahri
package icannclient

import (
	"net/http"
	"os"
	"time"
)

var mIsLindex bool
var mLastAuthenticationAttempt time.Time

const (
	GET  = "GET"
	HEAD = "HEAD"
	POST = "POST"

	czdsAPIBasedURL         = "https://czds-api.icann.org"
	czdsAPIDownloadLinksURL = "https://czds-api.icann.org/czds/downloads/links"
	authenticateBaseURL     = "https://account-api.icann.org/api/authenticate"
)

// configData is used to initialize variables
// from environment file.
type configData struct {
	AppDataDir           string
	UserAgent            string
	IcannAccountUserName string
	IcannAccountPassword string
	ApprovedTLD          []string
	ZoneFileDir          string
}

// IcannAPI defines the structure of hte IIcannAPI interface.
type IcannAPI struct {

	// AppDataDir is the directory (on the volume) that zone files will be downloaded to.
	AppDataDir string

	// UserAgent is required for all ICANN API calls; its format is:
	// <name of you product> / <version> <comment about your product>
	UserAgent string

	// ICANN person account username.
	UserName string

	// Password is the ICANN person account password.
	Password string

	// ApprovedTLD is an array of TLDs e.g. com, net.
	ApprovedTLD []string

	// Authenticated is used by callers to get the status of the authentication.
	Authenticated bool

	// AccessToken is available to callers to use for Bearer in the Authorization header.
	AccessToken JWT

	// isDirty is used to mark the first-time use of the app; so that
	// the 120 second wait is skipped when this app is first launched.
	isDirty bool
}

type JWT struct {
	Token           string
	DateTimeIssued  time.Time
	DateTimeExpires time.Time
}

type HTTPResult struct {
	StatusCode      int
	Error           error
	ResponseBody    []byte
	ResponseHeaders http.Header
}

type IcannClient struct {
	IcannAPI IIcannAPI
	CzdsAPI  ICzdsAPI
}

type autResult struct {
	AccessToken string `json:"accessToken"`
	Message     string `json:"message"`
}

type ZoneFileStatus struct {
	HTTPResult       HTTPResult
	OriginalFileName string // e.g. com.txt.gz
	FileLength       uint64
	TLDType          string // e.g. com
}

// TeeWriter defines the structure of the callback,
// to get status of the download in porgress.
type TeeWriter struct {
	TotalDownloaded uint64
	File            *os.File
	TempFilePath    string
	FileName        string
	TLDType         string
	StartTime       time.Time
}
