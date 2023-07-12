package main

import (
	icann "github.com/kambahr/go-icann-api-client"
)

func main() {

	icn := icann.NewIcannAPIClient()

	icn.CzdsAPI.Run()
}
