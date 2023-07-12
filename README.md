# ICANN API Client for Go

## Automates downloading zone files from the ICANN API site
Runs all needed to download zone-files periodically -- via one call.

## Automation Features

### Renews the OAuth 2.0 JWT every 24 hours
A new JWT token can be issued (per IP Addr) every 2 minutes; and each token is valid for 24 hours.
A separate instance keeps track of the JWT token issuance to ensure that no API request takes place with an 
expired token.

### Downloads approved TLDs every 48 hours
According to ICANN terms, each tld must be downloaded no more than once in 24 hours. Considering the large amount of information to process + the time it takes to prepare the results for a purpose (i.e. indexing), 48 hours is deemed to 
be the minimum time between downloads. 

## Security
### Required args
The following variables must be set via the environment variables:

  SALT_PHRASE.................................... this can be any word or phrase<br>
  ICANN_ACCOUNT_USERNAME........ usually the email used to setup the ICANN account<br>
  ICANN_ACCOUNT_PASSWORD........ ICANN account password<br>
  USER_AGENT...................................... user-agent in format: &lt;product name&gt; / &lt;version&gt; &lt;comment&gt;<br>
  APPROVED_TLDS............................... approved tld names, separated by comma (e.g. com,net)<br>
  HOURS_TO_WAIT_BETWEEN_DOWNLOADS............. hours to wait to download the same type of file (default is 24)<br>

Please, note that SALT_PHRASE is not required; if blank, an empty salt-phrase will be used.

### Essential args using the icann.env file
If the icann.env file exists in the install-directory, it will be used to read required args into
environment variables (otherwise the machine or user-profile env vars will be used).

If a plain-text value is detected in the icann.env file, it will be encrypted on the first-run -- including 
that of the SALT_PHRASE. Any key/value can be omitted from the icann.env, provided the equivalent exists in 
the machine or user-profile environment.

### Essential args without using the icann.env file
If the icann.env file does not exist, then the env vars are still expected to exist via that of the system or user-profile.

## Usage
```go
package main
import (
	icann "github.com/kambahr/go-icann-client"
)
func main() {

	icn := icann.NewIcannAPIClient()

	icn.CzdsAPI.Run()
}
```