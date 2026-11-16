// Command pwverify checks the HMAC-SHA256 signature of a PodWarden incident report.
//
//	pwverify -key "$HMAC_SIGNING_KEY" incident.json
//
// Exit codes: 0 = valid, 1 = signature mismatch (tampered or wrong key), 2 = usage/IO error.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/0xBrdn/PodWarden/internal/k8s"
)

func main() {
	key := flag.String("key", os.Getenv("HMAC_SIGNING_KEY"), "HMAC signing key (default: $HMAC_SIGNING_KEY)")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: pwverify [-key KEY] <incident.json>")
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() != 1 || *key == "" {
		flag.Usage()
		os.Exit(2)
	}

	data, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}

	ok, err := k8s.VerifyReport(data, *key)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	if !ok {
		fmt.Println("INVALID - signature mismatch (report tampered with, or wrong key)")
		os.Exit(1)
	}
	fmt.Println("VALID - signature matches")
}
