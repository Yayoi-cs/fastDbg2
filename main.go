package main

import (
	"fmt"
	"os"

	"fastdbg2/internal/shellcmd"
)

func main() {
	if code, handled := shellcmd.Helper(os.Args[1:]); handled {
		os.Exit(code)
	}
	if err := runCLI(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "fastDbg2:", err)
		os.Exit(1)
	}
}
