// Command polinchaser-scan runs the detection engine on a local directory.
// It proves the engine is independent of GitHub and is usable from CI.
// Exit codes: 0 clean, 1 findings, 2 scan incomplete/failed/timed out.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/Ferousco-dev/polinchaser/pkg/scanner"
)

func main() {
	asJSON := flag.Bool("json", false, "emit JSON")
	timeout := flag.Duration("timeout", 5*time.Minute, "scan timeout")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: polinchaser-scan [-json] [-timeout 5m] <dir>")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	res := scanner.New(scanner.BuiltinRules()).Scan(ctx, scanner.DirSource{Root: flag.Arg(0)})
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
	} else {
		fmt.Println(res)
		for _, f := range res.Findings {
			fmt.Printf("[%s/%s] %s:%d %s (%s)\n", f.Severity, f.Confidence, f.Path, f.LineStart, f.Title, f.RuleID)
		}
		for _, s := range res.Skipped {
			fmt.Printf("skipped %s (%s)\n", s.Path, s.Reason)
		}
	}
	switch res.Status {
	case scanner.StatusClean:
	case scanner.StatusFindings:
		os.Exit(1)
	default:
		os.Exit(2)
	}
}
