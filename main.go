package main

import (
	"fmt"
	"os"
)

func main() {
	if err := runCLI(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "fastDbg2:", err)
		os.Exit(1)
	}
}
