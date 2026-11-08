// Package detect finds which services run on the server and which Guards to enable (SPEC §8.3).
package detect

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// rule maps process names (as in /proc/<pid>/comm) to a detected label and a guard.
type rule struct {
	procs []string
	label string
	guard string
}

var rules = []rule{
	{[]string{"master", "postfix"}, "postfix", "mail"}, // Postfix's main process is named "master"
	{[]string{"exim4", "exim"}, "exim", "mail"},
	{[]string{"dovecot"}, "dovecot", "mail"},
	{[]string{"nginx"}, "nginx", "web"},
	{[]string{"apache2", "httpd"}, "apache", "web"},
	{[]string{"php-fpm"}, "php-fpm", "web"},
	{[]string{"node"}, "node", "web"},
	{[]string{"dotnet"}, "dotnet", "web"},
	{[]string{"asterisk"}, "asterisk", "voice"},
	{[]string{"freeswitch"}, "freeswitch", "voice"},
	{[]string{"kamailio"}, "kamailio", "voice"},
	{[]string{"postgres"}, "postgresql", "database"},
	{[]string{"mysqld", "mariadbd"}, "mysql", "database"},
	{[]string{"redis-server"}, "redis", "database"},
	{[]string{"dockerd"}, "docker", "containers"},
}

// Run scans running processes under procRoot (normally "/proc").
func Run(procRoot string) (detected, guards []string) {
	running := processNames(procRoot)
	return Match(running)
}

// Match is the pure part of detection, separated for tests.
func Match(running map[string]bool) (detected, guards []string) {
	d := map[string]bool{}
	g := map[string]bool{"server": true}
	for _, r := range rules {
		for _, p := range r.procs {
			if running[p] || hasPrefix(running, p+"-") || (p == "php-fpm" && hasPrefix(running, "php-fpm")) {
				// "master" alone is ambiguous; only count it as Postfix when postfix files exist.
				if p == "master" && !postfixInstalled() {
					continue
				}
				d[r.label] = true
				g[r.guard] = true
			}
		}
	}
	return keys(d), keys(g)
}

func processNames(procRoot string) map[string]bool {
	out := map[string]bool{}
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if !e.IsDir() || !isDigits(e.Name()) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(procRoot, e.Name(), "comm"))
		if err != nil {
			continue
		}
		out[strings.TrimSpace(string(b))] = true
	}
	return out
}

var postfixInstalled = func() bool {
	_, err := os.Stat("/etc/postfix/main.cf")
	return err == nil
}

func hasPrefix(m map[string]bool, prefix string) bool {
	for k := range m {
		if strings.HasPrefix(k, prefix) {
			return true
		}
	}
	return false
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
