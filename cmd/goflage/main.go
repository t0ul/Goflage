// Command goflage scrubs PII/secrets from stdin and prints the redacted text to
// stdout; a summary of what was removed goes to stderr.
//
//	echo "contact jane@example.org, key AKIAIOSFODNN7EXAMPLE" | goflage
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/t0ul/goflage"
)

func main() {
	in, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "goflage: read error:", err)
		os.Exit(1)
	}
	clean, findings := goflage.New().Scrub(string(in))
	fmt.Print(clean)
	if len(findings) > 0 {
		fmt.Fprintln(os.Stderr, "\n[goflage] redacted:")
		for _, f := range findings {
			fmt.Fprintf(os.Stderr, "  %s x%d\n", f.Entity, f.Count)
		}
	}
}
