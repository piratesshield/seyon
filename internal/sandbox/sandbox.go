// Package sandbox resolves the isolation intent for a spawned black-box target
// into a concrete runnable command. Its primary job is egress denial: when the
// engine spawns an untrusted MCP server for active probing, the server must not
// be able to reach the network (so it cannot exfiltrate or phone home). On
// Linux this is done by running the child in a fresh, empty network namespace
// via `unshare`. When that is unavailable, the sandbox reports that isolation
// was NOT applied and lets the caller decide — it never silently pretends a
// child is contained when it is not.
package sandbox

import (
	"context"
	"os/exec"
	"time"
)

// Policy is the isolation the caller wants for a spawned target.
type Policy struct {
	// DenyEgress asks for the child to run with no outbound network access.
	DenyEgress bool
}

// Plan is the resolved command plus an honest account of what was applied.
type Plan struct {
	Name           string   // program to exec
	Args           []string // its arguments
	EgressIsolated bool     // true only if network isolation was actually applied
	Method         string   // how isolation was achieved, or why it was not
}

// Build resolves policy into a command that runs `name args...`. When egress
// denial is requested and a working network-namespace wrapper is available, the
// command is wrapped so the child has no network; otherwise the original
// command is returned with EgressIsolated=false and Method explaining why.
func Build(policy Policy, name string, args []string) Plan {
	if !policy.DenyEgress {
		return Plan{Name: name, Args: args, EgressIsolated: false, Method: "egress isolation not requested"}
	}
	if unshareNetWorks() {
		// `unshare -n` places the child in a new network namespace with only a
		// down loopback: no route off-host. -r maps the caller to root inside the
		// namespace so an unprivileged process may create it.
		wrapped := append([]string{"-rn", name}, args...)
		return Plan{Name: "unshare", Args: wrapped, EgressIsolated: true, Method: "unshare -rn (empty network namespace)"}
	}
	return Plan{Name: name, Args: args, EgressIsolated: false, Method: "no network-isolation mechanism available (unshare unusable)"}
}

// unshareNetWorks reports whether `unshare -rn` can create a network namespace
// in this environment. It probes once with a trivial command.
func unshareNetWorks() bool {
	if _, err := exec.LookPath("unshare"); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// `true` exits 0; if the namespace cannot be created, unshare fails first.
	return exec.CommandContext(ctx, "unshare", "-rn", "true").Run() == nil
}
