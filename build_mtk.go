package main

import (
	"fmt"
	"net"
	"os"
	"strings"
)

func buildMikrotik(policies []Policy, objects Objects, services Services) string {
	var iplists = make(map[string]int8)
	var rules strings.Builder
	rules.WriteString("/ip firewall address-list\n")

	for _, p := range policies {
		if p.Disabled || p.IsZonePolicy() {
			continue
		}

		// For items with more than one IP, we use address lists
		for _, src := range p.Sources {
			names, lookup := objects.Lookup(p.From, src)
			if len(lookup) == 0 {
				_, _ = fmt.Fprintln(os.Stderr, p.From+" "+src+" not found")
				continue
			}

			listName := p.From + "__" + src

			if _, ok := iplists[listName]; !ok && len(lookup) > 1 {
				for idx, l := range lookup {
					rules.WriteString("add list=")
					rules.WriteString(listName)
					rules.WriteString(" address=")
					rules.WriteString(l.String())
					rules.WriteString(" comment=\"")
					rules.WriteString(names[idx])
					rules.WriteString("\"\n")
				}

				iplists[listName] = 1
			}
		}
		for _, dst := range p.Destinations {
			names, lookup := objects.Lookup(p.To, dst)
			if len(lookup) == 0 {
				_, _ = fmt.Fprintln(os.Stderr, p.To+" "+dst+" not found")
				continue
			}

			listName := p.To + "__" + dst

			if _, ok := iplists[listName]; !ok && len(lookup) > 1 {
				for idx, l := range lookup {
					rules.WriteString("add list=")
					rules.WriteString(listName)
					rules.WriteString(" address=")
					rules.WriteString(l.String())
					rules.WriteString(" comment=\"")
					rules.WriteString(names[idx])
					rules.WriteString("\"\n")
				}
			}

			iplists[listName] = 1
		}
	}

	rules.WriteString("\n\n/ip firewall filter\n")

	for _, p := range policies {
		if p.Disabled || p.IsZonePolicy() {
			continue
		}

		rules.WriteString("# ")
		rules.WriteString(p.String())
		rules.WriteString("\n")

		for _, serviceName := range p.Services {
			// First part: rule with literal IP addresses
			var src []*net.IPNet
			var dst []*net.IPNet
			var srcNames []string
			var dstNames []string
			var srcAddressLists []string
			var dstAddressLists []string

			for _, srcAddress := range p.Sources {
				_, lookup := objects.Lookup(p.From, srcAddress)
				if len(lookup) > 1 {
					srcAddressLists = append(srcAddressLists, p.From+"__"+srcAddress)
				} else if len(lookup) == 1 {
					src = append(src, lookup...)
					srcNames = append(srcNames, srcAddress)
				}
			}
			for _, dstAddress := range p.Destinations {
				_, lookup := objects.Lookup(p.To, dstAddress)
				if len(lookup) > 1 {
					dstAddressLists = append(dstAddressLists, p.To+"__"+dstAddress)
				} else if len(lookup) == 1 {
					dst = append(dst, lookup...)
					dstNames = append(dstNames, dstAddress)
				}
			}

			if serviceName == "ANY" {
				for idx, srcAddress := range src {
					for jdx, dstAddress := range dst {
						rules.WriteString(mikrotikRule(p, p.From+"__"+p.To, srcNames[idx], srcAddress, "", dstNames[jdx], dstAddress, "", "", nil))
					}
					for _, dstList := range dstAddressLists {
						rules.WriteString(mikrotikRule(p, p.From+"__"+p.To, srcNames[idx], srcAddress, "", "", nil, dstList, "", nil))
					}
				}
				for _, srcList := range srcAddressLists {
					for jdx, dstAddress := range dst {
						rules.WriteString(mikrotikRule(p, p.From+"__"+p.To, "", nil, srcList, dstNames[jdx], dstAddress, "", "", nil))
					}
					for _, dstList := range dstAddressLists {
						rules.WriteString(mikrotikRule(p, p.From+"__"+p.To, "", nil, srcList, "", nil, dstList, "", nil))
					}
				}
				continue
			}

			if _, ok := services[serviceName]; !ok {
				panic("services not found: " + serviceName)
			}

			for _, proto := range services[serviceName].AllProtocols() {
				for idx, srcAddress := range src {
					for jdx, dstAddress := range dst {
						rules.WriteString(mikrotikRule(p, p.From+"__"+p.To, srcNames[idx], srcAddress, "", dstNames[jdx], dstAddress, "", proto, services[serviceName]))
					}
					for _, dstList := range dstAddressLists {
						rules.WriteString(mikrotikRule(p, p.From+"__"+p.To, srcNames[idx], srcAddress, "", "", nil, dstList, proto, services[serviceName]))
					}
				}
				for _, srcList := range srcAddressLists {
					for jdx, dstAddress := range dst {
						rules.WriteString(mikrotikRule(p, p.From+"__"+p.To, "", nil, srcList, dstNames[jdx], dstAddress, "", proto, services[serviceName]))
					}
					for _, dstList := range dstAddressLists {
						rules.WriteString(mikrotikRule(p, p.From+"__"+p.To, "", nil, srcList, "", nil, dstList, proto, services[serviceName]))
					}
				}
			}
		}
		rules.WriteString("\n")
	}

	return rules.String()
}

func mikrotikRule(p Policy, chain string, srcName string, src *net.IPNet, srcList string, dstName string, dst *net.IPNet, dstList string, proto string, svc ServiceList) string {
	var ret strings.Builder
	ret.WriteString("add chain=")
	ret.WriteString(chain)

	if srcList == "" && !src.IP.Equal(net.IPv4zero) {
		ret.WriteString(" src-address=")
		ret.WriteString(src.String())
	} else if srcList != "" {
		ret.WriteString(" src-address-list=")
		ret.WriteString(srcList)
	}

	if dstList == "" && !dst.IP.Equal(net.IPv4zero) {
		ret.WriteString(" dst-address=")
		ret.WriteString(dst.String())
	} else if dstList != "" {
		ret.WriteString(" dst-address-list=")
		ret.WriteString(dstList)
	}

	if proto != "" {
		ret.WriteString(" protocol=" + proto)
	}
	if proto == "tcp" || proto == "udp" {
		var srcPorts []string
		var dstPorts []string
		for _, s := range svc {
			if s.Protocol == proto {
				if s.SrcPortStart != 0 && s.SrcPortEnd != 65535 {
					srcPorts = append(srcPorts, fmt.Sprintf("%d-%d", s.SrcPortStart, s.SrcPortEnd))
				}
				if s.DstPortStart != 0 && s.DstPortEnd != 65535 {
					dstPorts = append(dstPorts, fmt.Sprintf("%d-%d", s.DstPortStart, s.DstPortEnd))
				}
			}
		}
		if len(srcPorts) > 0 {
			ret.WriteString(" src-port=")
			ret.WriteString(strings.Join(srcPorts, ","))
		}
		if len(dstPorts) > 0 {
			ret.WriteString(" dst-port=")
			ret.WriteString(strings.Join(dstPorts, ","))
		}
	} else if proto == "icmp" {
		ret.WriteString(" icmp-options=8:0-255")
	}

	switch {
	case p.Action == ActionPermit:
		ret.WriteString(" action=accept")
	case p.Action == ActionReject:
		ret.WriteString(" action=reject")
	case p.Action == ActionDeny:
		ret.WriteString(" action=drop")
	}

	if p.Log {
		ret.WriteString(" log=yes")
	}

	ret.WriteString(" comment=\"ID: ")
	ret.WriteString(fmt.Sprint(p.ID))
	if len(p.Name) > 0 {
		ret.WriteString(" - ")
		ret.WriteString(strings.ReplaceAll(p.Name, "\"", ""))
	}
	ret.WriteString(" - ")
	if len(srcName) > 0 {
		ret.WriteString(srcName)
	} else {
		ret.WriteString(srcList)
	}
	ret.WriteString(" -> ")
	if len(dstName) > 0 {
		ret.WriteString(dstName)
	} else {
		ret.WriteString(dstList)
	}
	ret.WriteString("\"\n")
	return ret.String()
}
