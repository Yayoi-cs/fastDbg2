package debugger

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"fastdbg2/display"
)

func latestHelpText(t *testing.T, command string) string {
	t.Helper()
	var output bytes.Buffer
	controller := New(&output, display.Renderer{})
	quit, err := controller.Execute(context.Background(), "help", command)
	if quit || err != nil {
		t.Fatalf("help %q: quit=%t err=%v", command, quit, err)
	}
	return output.String()
}

func TestLatestHelpDescribesVerifiedLoadedSymbolResolution(t *testing.T) {
	for _, command := range []string{"print", "p", "memory", "break", "b"} {
		text := latestHelpText(t, command)
		for _, wanted := range []string{
			"verified loaded scope", "case-sensitive", "MODULE!NAME", "NAME@VERSION", "MODULE!NAME@VERSION",
			"module ID", "@@", "Same-address aliases collapse", "different addresses are ambiguous", "Library-local", "TLS/IFUNC addresses are not guessed",
		} {
			if !strings.Contains(text, wanted) {
				t.Fatalf("help %s missing %q: %s", command, wanted, text)
			}
		}
		for _, obsolete := range []string{"exact main-executable symbol", "exact main symbols", "main-only"} {
			if strings.Contains(text, obsolete) {
				t.Fatalf("help %s retains obsolete scope %q: %s", command, obsolete, text)
			}
		}
	}
}

func TestLatestBreakHelpSeparatesPendingLoaderAndHardErrors(t *testing.T) {
	text := latestHelpText(t, "break")
	for _, wanted := range []string{
		"Before start", "verified unpublished startup loader", "run/continue retry at verified hooks",
		"Ordinary constructors", "IFUNC/audit", "not guaranteed", "still-missing symbol is an error", "the stop is retained", "Unload/rebinding tracking is not provided",
		"future dlopen is not silently awaited", "User stops and signals remain visible",
		"one bare or backtick-quoted symbol", "compound/register-dependent expressions are unsupported", "not loader-state polling", "step stops remain visible",
	} {
		if !strings.Contains(text, wanted) {
			t.Fatalf("break help missing %q: %s", wanted, text)
		}
	}
	if text := latestHelpText(t, "start"); !strings.Contains(text, "without advancing past exec") || !strings.Contains(text, "remain pending") {
		t.Fatalf("start help overpromises installation or advances to main: %s", text)
	}
	if text := latestHelpText(t, "run"); !strings.Contains(text, "Loader-pending") || !strings.Contains(text, "errors prevent automatic resume") {
		t.Fatalf("run help obscures hard failures: %s", text)
	}
}

func TestLatestPagerHelpPreservesTerminalAndPipeContracts(t *testing.T) {
	for _, command := range []string{"sym", "symbol", "tel", "telescope"} {
		text := latestHelpText(t, command)
		for _, wanted := range []string{
			"stdin and stdout are real terminals", "TERM is usable", "less -SR", "alternate screen and keypad modes", "Pipes and nonterminal inputs print directly",
			"NO_COLOR", "q returns", "Ctrl-C", "stays in less", "terminal restoration", "less is missing", "warning", "not redumped", "logical row remains one line", "left/right", "resize", "screen restoration is unconfirmed",
		} {
			if !strings.Contains(text, wanted) {
				t.Fatalf("pager help %s missing %q: %s", command, wanted, text)
			}
		}
		if strings.Contains(text, "-XSR") || strings.Contains(text, "--no-keypad") {
			t.Fatalf("pager help retains screen restoration workaround: %s", text)
		}
	}
	if text := latestHelpText(t, "tel"); !strings.Contains(text, "COUNT defaults to 128 qwords") || !strings.Contains(text, "bounded at 512") || !strings.Contains(text, "Default depth is 4") {
		t.Fatalf("telescope defaults diverge from legacy pager contract: %s", text)
	}
}

func TestLatestGeneralHelpDescribesConfirmedPromptAndSymbolScope(t *testing.T) {
	text := latestHelpText(t, "")
	for _, wanted := range []string{"confirmed selected-thread instruction address", "[fastDbg2]$", "verified loaded scope", "MODULE!NAME", "NAME@VERSION", "never main-first guesses", "verified startup loader publication", "Missing less"} {
		if !strings.Contains(text, wanted) {
			t.Fatalf("general help missing %q: %s", wanted, text)
		}
	}
	if strings.Contains(text, "exact main-executable symbols") || strings.Contains(text, "Expression resolution uses exact main symbols") {
		t.Fatalf("general help retains main-only resolution: %s", text)
	}
}

func TestLatestFunctionHelpSeparatesExpressionScopeFromExtentSource(t *testing.T) {
	text := latestHelpText(t, "disass func")
	for _, wanted := range []string{"Default scope is the independently proven main executable", "verified loaded symbol scope", "MODULE!NAME", "independently limits the function-extent source", "No automatic cross-module fallback"} {
		if !strings.Contains(text, wanted) {
			t.Fatalf("function help missing %q: %s", wanted, text)
		}
	}
	if strings.Contains(text, "EXPR lookup remains main-only") {
		t.Fatal("function help still narrows expression resolution to main")
	}
}
