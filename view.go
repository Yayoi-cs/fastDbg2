package main

import "io"

func writeHelp(output io.Writer) error {
	_, err := io.WriteString(output, "fastDbg2\n\nUsage:\n  fastDbg2 [-h|--help]\n\nThe debugger foundation is available as Go packages.\nThe command interface is not implemented yet.\n")
	return err
}
