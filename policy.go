package main

import (
	"fmt"
	"strings"
)

const (
	ActionPermit = "permit"
	ActionReject = "reject"
	ActionDeny   = "deny"
	NatSrc       = "nat src"
	NatDst       = "nat dst"
)

type Policy struct {
	ID       int
	Name     string
	Disabled bool

	// Zones
	From string
	To   string

	// Addresses
	Sources      []string
	Destinations []string

	// Ports/protocols
	Services    []string
	Application string

	// NAT
	NAT        string
	NATAddress string
	NATPort    int

	// Actions
	Action  string
	Log     bool
	LogInit bool
}

func (p *Policy) IsValid() bool {
	return p.ID > 0 &&
		len(p.From) > 0 &&
		len(p.To) > 0 &&
		len(p.Sources) > 0 &&
		len(p.Destinations) > 0 &&
		len(p.Services) > 0 &&
		(p.Action == ActionPermit || p.Action == ActionReject || p.Action == ActionDeny) &&
		(p.NAT == "" || p.NAT == NatSrc || p.NAT == NatDst)
}

func (p *Policy) Equals(q *Policy) bool {
	if !stringSliceEqual(p.Sources, q.Sources) {
		return false
	}
	if !stringSliceEqual(p.Destinations, q.Destinations) {
		return false
	}
	if !stringSliceEqual(p.Services, q.Services) {
		return false
	}

	// Can't use reflect.DeepEqual because we don't mind the order in a slice

	return p.ID == q.ID &&
		p.Name == q.Name &&
		p.Disabled == q.Disabled &&
		p.From == q.From &&
		p.To == q.To &&
		p.Application == q.Application &&
		p.NAT == q.NAT &&
		p.NATAddress == q.NATAddress &&
		p.NATPort == q.NATPort &&
		p.Action == q.Action &&
		p.Log == q.Log &&
		p.LogInit == q.LogInit
}

func (p *Policy) String() string {
	return fmt.Sprint("ID: ", p.ID, " Name: ", p.Name, " Disabled: ", p.Disabled, " From: ", p.From, " To: ", p.To,
		" Sources: ", p.Sources, " Destinations: ", p.Destinations, " Services: ", p.Services, " Application: ", p.Application,
		" NAT: ", p.NAT, " NATAddress: ", p.NATAddress, " NATPort: ", p.NATPort, " Action: ", p.Action, " Log: ", p.Log,
		" LogInit: ", p.LogInit)
}

func (p *Policy) IsZonePolicy() bool {
	return strings.ToLower(p.Sources[0]) == "any" && strings.ToLower(p.Destinations[0]) == "any" &&
		(p.Action == ActionReject || p.Action == ActionDeny)
}

func stringSliceEqual(p, q []string) bool {
	if len(p) != len(q) {
		return false
	}

	for _, a := range p {
		var found = false
		for _, b := range q {
			if a == b {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}
