package main

import "io"

func writeHelp(output io.Writer) error {
	return writeCLIText(output, "fastDbg2\n\nUsage:\n  fastDbg2 [-h|--help]\n  fastDbg2 --interactive\n  fastDbg2 [--interactive] -f FILE [-- ARGS...]\n  fastDbg2 [--interactive] -p PID\n\nLinux/amd64 native debugger.\n-f selects an executable without starting it; use start or run in the console.\n-p attaches to a process. -f and -p are mutually exclusive.\nUse help for debugger commands. Tab completes command names only.\nTarget arguments are literal: quoting and backslash escapes are supported in the console,\nbut shell expansion, pipelines, redirection, and command substitution are not.\nCtrl-C cancels input or interrupts a running command; SIGTERM shuts down the debugger.\n")
}

func writeCLIText(output io.Writer, text string) error {
	n, err := io.WriteString(output, text)
	if err == nil && n != len(text) {
		return io.ErrShortWrite
	}
	return err
}
