package main

import (
	"net"
	"strings"
)

type PolicyObject struct {
	Address      *net.IPNet
	GroupMembers []string
}

type Objects map[string]map[string]*PolicyObject

func (o Objects) Add(zone string, name string, address *net.IPNet) {
	if _, ok := o[zone]; !ok {
		o[zone] = make(map[string]*PolicyObject)
		o[zone][name] = &PolicyObject{}
	}
	o[zone][name] = &PolicyObject{Address: address}
}

func (o Objects) AddToGroup(zone string, name string, objectToAdd string) {
	if _, ok := o[zone]; !ok {
		o[zone] = make(map[string]*PolicyObject)
		o[zone][name] = &PolicyObject{}
	}
	if _, ok := o[zone][name]; !ok {
		o[zone][name] = &PolicyObject{}
	}
	o[zone][name].GroupMembers = append(o[zone][name].GroupMembers, objectToAdd)
}

func (o Objects) Lookup(zone string, name string) ([]string, []*net.IPNet) {
	if strings.ToLower(name) == "any" {
		return []string{name}, []*net.IPNet{{IP: net.IPv4zero, Mask: net.IPMask(net.IPv4zero)}}
	}

	if strings.HasPrefix(name, "MIP(") {
		return []string{name}, []*net.IPNet{{
			IP:   net.ParseIP(strings.ReplaceAll(strings.ReplaceAll(name, ")", ""), "MIP(", "")),
			Mask: net.IPMask(net.IPv4bcast),
		}}
	} else if strings.HasPrefix(name, "VIP(") {
		return []string{name}, []*net.IPNet{{
			IP:   net.ParseIP(strings.ReplaceAll(strings.ReplaceAll(name, ")", ""), "VIP(", "")),
			Mask: net.IPMask(net.IPv4bcast),
		}}
	}

	if _, ok := o[zone]; !ok {
		return nil, nil
	}
	if _, ok := o[zone][name]; !ok {
		return nil, nil
	}

	if len(o[zone][name].GroupMembers) > 0 {
		var names []string
		var ret []*net.IPNet
		for _, obj := range o[zone][name].GroupMembers {
			n, addresses := o.Lookup(zone, obj)
			names = append(names, n...)
			ret = append(ret, addresses...)
		}

		var dedup []*net.IPNet
		var dedupNames []string
		for idx, ip := range ret {
			var found = false
			for _, newip := range dedup {
				if ip.IP.Equal(newip.IP) && ip.Mask.String() == newip.Mask.String() {
					found = true
				}
			}
			if !found {
				dedup = append(dedup, ip)
				dedupNames = append(dedupNames, names[idx])
			}
		}

		return dedupNames, dedup
	}
	return []string{name}, []*net.IPNet{o[zone][name].Address}
}
