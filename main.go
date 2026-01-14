package main

import (
	"flag"
	"fmt"
	"os"

	"dnsleaktest/internal/app"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	versionFlag := flag.Bool("version", false, "print version and exit")
	shortFlag := flag.Bool("short", false, "Run short test (leak only)")
	flag.Parse()

	if *versionFlag {
		fmt.Printf("dnsleaktest %s (commit: %s, built at: %s)\n", version, commit, date)
		os.Exit(0)
	}

	app.Main(*shortFlag)
}
