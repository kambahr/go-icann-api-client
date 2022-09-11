// (c) Kamiar Bahri
package icannclient

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// NewIcannAPIClient creates a new instance of the icann interface.
// It runs the authentication immediately.
func NewIcannAPIClient() *IcannClient {

	// Set the env. right away. This encrypts the plain
	// text in the env file; if any.
	cnf := setEnv()

	tick := time.Tick(time.Second)
	for i := 15; i >= 1; i-- {
		<-tick
		fmt.Printf("\rdownload will start is %02d seconds ", i)
	}

	var icn IcannClient
	var authToken JWT
	var authenticated bool

	// Initialize the IcannAPI interface
	icn.IcannAPI = &IcannAPI{cnf.ZoneFileDir, cnf.UserAgent,
		cnf.IcannAccountUserName, cnf.IcannAccountPassword, cnf.ApprovedTLD, authenticated, authToken, false}

	// CzdsAPI expands the IcannAPI interface with more functionaliy; so its IcannAPI instance
	// must be initialized accordingly.
	icn.CzdsAPI = &CzdsAPI{
		&IcannAPI{cnf.ZoneFileDir, cnf.UserAgent,
			cnf.IcannAccountUserName, cnf.IcannAccountPassword, cnf.ApprovedTLD, authenticated, authToken, false},
	}

	os := runtime.GOOS
	if os == "linux" {
		mIsLindex = true
	}

	// Authenticate on the first run; after that --
	// the auth token is renewed periodically. If
	// authentiation is not successfull there will
	// be a fatal error here.
	icn.CzdsAPI.ICANN().Authenticate()

	// send the results to the screen, in case the console
	// is being watched; this line will be replaced shortly
	// after it's displayed.
	ConsoleClearLastLine()
	fmt.Println("Authenticated:", icn.CzdsAPI.ICANN().Authenticated)

	go fireAPIRun(&icn)

	return &icn
}

// fireAPIRun starts ICANN() with a two-minute delay
// so that there is no wait-time on the first run; hence
// no unnecessary delay after the first (successfull) authentication.
func fireAPIRun(icn *IcannClient) {
	tick := time.Tick(time.Second)
	for i := 121; i >= 1; i-- {
		<-tick
	}
	go icn.CzdsAPI.ICANN().Run()
}

func setEnv() configData {
	var cnf configData

	installPath, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		log.Fatal(err)
	}
	envFilePath := installPath + "/icann.env"

	SetEnvFromFile(envFilePath)

	// All required args are initialized from environment variables.
	// So, if there is no icann.env file; then the following variables
	// must have been se on the machine or user-profile level:
	//
	//   SALT_PHRASE
	//   ICANN_ACCOUNT_USERNAME
	//   ICANN_ACCOUNT_PASSWORD
	//   USER_AGENT
	//   APPROVED_TLDS

	cnf.IcannAccountUserName = os.Getenv("ICANN_ACCOUNT_USERNAME")
	cnf.IcannAccountPassword = os.Getenv("ICANN_ACCOUNT_PASSWORD")

	if cnf.IcannAccountPassword == "" || cnf.IcannAccountUserName == "" {
		// stop the show; without username/password, there will be no API calls.
		log.Fatal("failed to get env variables")
	}

	// Note that ICANN API calls will fail without a proper user-agent.
	// userAgent has format of:
	//    <name of your product> / <version> <comment about your product>
	cnf.UserAgent = os.Getenv("USER_AGENT")
	if cnf.UserAgent == "" {
		// stop the show; without username/password, there will be no API calls.
		log.Fatal("failed to get env variables")
	}

	// Initialize the approvedTLD with your authrorized TLDs as the below example.
	// Note that you must have authorization for each TLD.
	str := strings.ToLower(os.Getenv("APPROVED_TLDS"))
	v := strings.Split(str, ",")
	for i := 0; i < len(v); i++ {
		cnf.ApprovedTLD = append(cnf.ApprovedTLD, v[i])
	}

	if os.Getenv("ICANN_ROOT_PATH") != "" {
		cnf.ZoneFileDir = fmt.Sprintf("%s/appdata/zone-files", os.Getenv("ICANN_ROOT_PATH"))
	} else {
		// default location for downloaded zone files is:
		// <install-path>/appdata/zone-files/<all downloaded *.gz files will reside here>
		cnf.ZoneFileDir = fmt.Sprintf("%s/appdata/zone-files", installPath)
	}

	if !FileOrDirExists(cnf.ZoneFileDir) {
		os.MkdirAll(cnf.ZoneFileDir, os.ModePerm)
	}

	return cnf
}
