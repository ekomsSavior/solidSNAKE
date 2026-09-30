// solidSNAKE - dev-time oracle: prints the Go payload registry Info() (default) or a
// conformance fixture of raw payload outputs for deterministic modules ("conformance").
// Run through the staged /tmp/interop-mod module (see scripts/interop.sh).
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"git.churchofmalware.org/ek0mssavi0r/Ranger-C3/internal/payloads"
)

type confCase struct {
	Name string            `json:"name"`
	Args map[string]string `json:"args"`
	Out  string            `json:"out"`
}

func main() {
	mode := ""
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}

	if mode == "exec" {
		// payloadref exec <name> [k=v ...] - generic probe used by the ad-hoc dual-side
		// diffs for side-effect modules (the conformance fixture only carries safe cases).
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: payloadref exec <name> [k=v ...]")
			os.Exit(2)
		}
		args := map[string]string{}
		for _, kv := range os.Args[3:] {
			i := strings.Index(kv, "=")
			if i < 0 {
				args[kv] = ""
				continue
			}
			args[kv[:i]] = kv[i+1:]
		}
		out, err := payloads.ExecuteByName(os.Args[2], args)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Print(string(out))
		return
	}

	if mode == "conformance" {
		cases := []confCase{
			{Name: "polyloader", Args: map[string]string{}}, // missing arg
			{Name: "polyloader", Args: map[string]string{"shellcode": ""}},
			{Name: "polyloader", Args: map[string]string{"shellcode": "QUJD"}},
			{Name: "polyloader", Args: map[string]string{"shellcode": "QUJD", "key": "aa"}},
			{Name: "polyloader", Args: map[string]string{"shellcode": "not!base64!"}},
			{Name: "dnstunnel", Args: map[string]string{"mode": "server"}}, // no network
			{Name: "dnstunnel", Args: map[string]string{"mode": "server", "domain": "t.example", "data": "abc"}},
		}
		for i := range cases {
			out, err := payloads.ExecuteByName(cases[i].Name, cases[i].Args)
			if err != nil {
				fmt.Fprintf(os.Stderr, "case %d: %v\n", i, err)
				os.Exit(1)
			}
			// Normalise the timestamp in place so the committed fixture is stable across runs
			// (field order is preserved; the solidSNAKE test ignores timestamps either way).
			var ts struct {
				Timestamp string `json:"timestamp"`
			}
			_ = json.Unmarshal(out, &ts)
			raw := string(out)
			if ts.Timestamp != "" {
				raw = strings.Replace(raw, ts.Timestamp, "1970-01-01T00:00:00Z", 1)
			}
			cases[i].Out = raw
		}
		data, err := json.MarshalIndent(cases, "", "  ")
		if err != nil {
			fmt.Fprintln(os.Stderr, "marshal:", err)
			os.Exit(1)
		}
		fmt.Println(string(data))
		return
	}

	data, err := json.MarshalIndent(payloads.Info(), "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "marshal:", err)
		os.Exit(1)
	}
	fmt.Println(string(data))
}
