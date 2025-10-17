package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

type osvQuery struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	Version string `json:"version"`
}

type osvResp struct {
	Vulns []struct {
		ID      string `json:"id"`
		Summary string `json:"summary"`
		// (fields trimmed; we only print ID & summary for now)
	} `json:"vulns"`
}

var scanCmd = &cobra.Command{
	Use:   "scan [path-to-package-lock.json]",
	Short: "Scan a Node.js project (package-lock.json) for vulnerabilities using OSV",
	Long:  "Parses package-lock.json (v2/v3 style), queries the OSV API per dependency, and prints only vulnerable packages.",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		lockfilePath := filepath.Clean(args[0])

		data, err := os.ReadFile(lockfilePath)
		if err != nil {
			fmt.Println("❌ Error reading lockfile:", err)
			os.Exit(1)
		}

		var lock map[string]any
		if err := json.Unmarshal(data, &lock); err != nil {
			fmt.Println("❌ Invalid JSON:", err)
			os.Exit(1)
		}

		// Extract deps from "packages" block (npm lockfile v2/v3).
		deps := extractNpmPackages(lock)
		if len(deps) == 0 {
			fmt.Println("⚠️  No dependencies found in lockfile (expected npm lockfile v2/v3).")
			return
		}

		fmt.Printf("🔎 Scanning %d packages from: %s\n", len(deps), lockfilePath)

		vulnCount := 0
		for _, d := range deps {
			// Skip the root "" entry and empty versions.
			if d.name == "" || d.version == "" {
				continue
			}

			// Build OSV query
			var q osvQuery
			q.Package.Ecosystem = "npm"
			q.Package.Name = d.name
			q.Version = d.version

			payload, _ := json.Marshal(q)
			resp, err := http.Post("https://api.osv.dev/v1/query", "application/json", bytes.NewBuffer(payload))
			if err != nil {
				fmt.Printf("  ❌ %s@%s → OSV query failed: %v\n", d.name, d.version, err)
				continue
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()

			var or osvResp
			if err := json.Unmarshal(body, &or); err != nil {
				fmt.Printf("  ❌ %s@%s → bad OSV response: %v\n", d.name, d.version, err)
				continue
			}

			if len(or.Vulns) > 0 {
				vulnCount += len(or.Vulns)
				fmt.Printf("  🚨 %s@%s — %d vuln(s)\n", d.name, d.version, len(or.Vulns))
				for _, v := range or.Vulns {
					// Print ID + short summary (trim to one line)
					s := strings.Split(strings.TrimSpace(v.Summary), "\n")[0]
					if len(s) > 110 {
						s = s[:110] + "…"
					}
					fmt.Printf("     • %s — %s\n", v.ID, s)
				}
			}
		}

		if vulnCount == 0 {
			fmt.Println("✅ No known vulnerabilities found for the packages in this lockfile (per OSV).")
		}
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
}

/********** helpers **********/

type dep struct {
	name    string
	version string
}

// extractNpmPackages finds packages in lockfile v2/v3: lock["packages"] is a map
// where keys are "", "node_modules/lodash", etc. We take the name from the key
// (strip "node_modules/") and version from the value's "version".
func extractNpmPackages(lock map[string]any) []dep {
	packagesAny, ok := lock["packages"]
	if !ok {
		return nil
	}
	packages, ok := packagesAny.(map[string]any)
	if !ok {
		return nil
	}

	out := make([]dep, 0, len(packages))
	for k, v := range packages {
		entry, ok := v.(map[string]any)
		if !ok {
			continue
		}
		ver, _ := entry["version"].(string)

		// Root package entry has key "" — skip it (no module name)
		if k == "" {
			continue
		}

		name := strings.TrimPrefix(k, "node_modules/")
		// Scoped packages appear as "node_modules/@scope/pkg" → keep as "@scope/pkg"
		if strings.HasPrefix(name, "@") && strings.Count(name, "/") >= 1 {
			parts := strings.SplitN(name, "/", 2)
			if len(parts) == 2 {
				name = parts[0] + "/" + parts[1]
			}
		} else if i := strings.Index(name, "/"); i >= 0 && !strings.HasPrefix(name, "@") {
			// For paths like "node_modules/foo/bar" (rare), keep only the first segment
			name = name[:i]
		}

		out = append(out, dep{name: name, version: ver})
	}
	return out
}
