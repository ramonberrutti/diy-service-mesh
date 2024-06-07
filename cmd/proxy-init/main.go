package main

import (
	"fmt"
	"os/exec"
)

func main() {
	// Configure the proxy
	commands := []*exec.Cmd{
		// Default accept
		exec.Command("iptables", "-t", "nat", "-P", "PREROUTING", "ACCEPT"),
		exec.Command("iptables", "-t", "nat", "-P", "INPUT", "ACCEPT"),
		exec.Command("iptables", "-t", "nat", "-P", "OUTPUT", "ACCEPT"),
		exec.Command("iptables", "-t", "nat", "-P", "POSTROUTING", "ACCEPT"),

		// Create custom chains
		exec.Command("iptables", "-t", "nat", "-N", "PROXY_INBOUND"),
		exec.Command("iptables", "-t", "nat", "-N", "PROXY_OUTBOUND"),

		// Jump to custom chains
		exec.Command("iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "-j", "PROXY_INBOUND"),
		exec.Command("iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-j", "PROXY_OUTBOUND"),

		// Set rules for custom chains: PROXY_INBOUND
		exec.Command("iptables", "-t", "nat", "-A", "PROXY_INBOUND", "-p", "tcp", "-j", "REDIRECT", "--to-port", "4000"),

		// Set rules for custom chains: PROXY_OUTBOUND
		// allow local traffic
		exec.Command("iptables", "-t", "nat", "-A", "PROXY_OUTBOUND", "-o", "lo", "-j", "RETURN"),
		exec.Command("iptables", "-t", "nat", "-A", "PROXY_OUTBOUND", "-d", "127.0.0.1/32", "-j", "RETURN"),

		// Ignore traffic from the proxy
		exec.Command("iptables", "-t", "nat", "-A", "PROXY_OUTBOUND", "-m", "owner", "--uid-owner", "1337", "-j", "RETURN"),

		// redirect all outbound traffic to port 5000
		exec.Command("iptables", "-t", "nat", "-A", "PROXY_OUTBOUND", "-p", "tcp", "-j", "REDIRECT", "--to-port", "5000"),
	}

	for _, cmd := range commands {
		if err := cmd.Run(); err != nil {
			fmt.Printf("failed to run command: %v\n", err)
		}
	}

	fmt.Println("Proxy initialized successfully!")
}
