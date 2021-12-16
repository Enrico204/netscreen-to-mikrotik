package main

import (
	"fmt"
	"os"
)

func main() {
	policies, objects, services := parse(os.Stdin)

	var filteredPolicies []Policy
	for _, p := range policies {
		if p.From == "Clients" || p.To == "Clients" {
			filteredPolicies = append(filteredPolicies, p)
		}
	}

	//nolint:forbidigo
	fmt.Println(buildMikrotik(filteredPolicies, objects, services))
}
