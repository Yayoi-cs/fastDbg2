package main

import (
	"fmt"
	"io"
)

func runCLI(args []string, output io.Writer) error {
	if len(args) == 0 || len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		return writeHelp(output)
	}
	return fmt.Errorf("command interface is not implemented: %q", args)
}
