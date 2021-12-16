package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var setAddressRx = regexp.MustCompile("^set address \"([^\"]+)\" \"([^\"]+)\" ([^ ]+) ?([^ ]+)?( \"([^\"]+)\")?$")
var setGroupAddressRx = regexp.MustCompile("^set group address \"([^\"]+)\" \"([^\"]+)\" add \"([^\"]+)\"$")
var setGroupAddressCreateRx = regexp.MustCompile("^set group address \"([^\"]+)\" \"([^\"]+)\"( comment .*)?$")
var setPolicyCreateRx = regexp.MustCompile("^set policy id ([0-9]+) (name \"([^\"]+)\" )?from \"([^\"]+)\" to \"([^\"]+)\" {2}\"([^\"]+)\" \"([^\"]+)\" \"([^\"]+)\" (nat src|nat dst)?( ip ([^ ]+))?( port ([0-9]+))? ?(permit|deny|reject) ?(log)?( traffic mbw 2000)?( schedule \"[^\"]+\")?")
var setPolicyRx = regexp.MustCompile("^set policy id ([0-9]+)$")
var setPolicyFlagsRx = regexp.MustCompile("^set policy id ([0-9]+) (disable|application) ?(\"([^\"]+)\")?$")
var setPolicyServiceRx = regexp.MustCompile("^set (service|dst-address|src-address) \"([^\"]+)\"$")
var setLogOptionsRx = regexp.MustCompile("^set log (.*)$")
var setServiceRx = regexp.MustCompile("^set service \"([^\"]+)\" protocol (tcp|udp|50|51) src-port ([0-9]+)-([0-9]+) dst-port ([0-9]+)-([0-9]+)( timeout [0-9]+)?$")
var setServiceContinueRx = regexp.MustCompile("^set service \"([^\"]+)\" \\+ (tcp|udp|50|51) src-port ([0-9]+)-([0-9]+) dst-port ([0-9]+)-([0-9]+)( timeout [0-9]+)?$")
var setServiceTimeoutRx = regexp.MustCompile("^set service \"([^\"]+)\" (timeout [0-9]+|session-cache)$")

func parse(reader io.Reader) ([]Policy, Objects, Services) {
	var policies []Policy
	var objects = make(Objects)
	var services = defaultServices()

	var lastService = ""

	var scanner = bufio.NewScanner(reader)
	for scanner.Scan() {
		var line = strings.TrimSpace(scanner.Text())
		switch {
		case setServiceContinueRx.MatchString(line):
			parts := setServiceContinueRx.FindAllStringSubmatch(line, -1)
			services.Add(lastService, Service{
				Protocol:     parts[0][2],
				SrcPortStart: mustInt(parts[0][3]),
				SrcPortEnd:   mustInt(parts[0][4]),
				DstPortStart: mustInt(parts[0][5]),
				DstPortEnd:   mustInt(parts[0][6]),
			})
		case setServiceRx.MatchString(line):
			parts := setServiceRx.FindAllStringSubmatch(line, -1)
			lastService = parts[0][1]
			services.Add(lastService, Service{
				Protocol:     parts[0][2],
				SrcPortStart: mustInt(parts[0][3]),
				SrcPortEnd:   mustInt(parts[0][4]),
				DstPortStart: mustInt(parts[0][5]),
				DstPortEnd:   mustInt(parts[0][6]),
			})
		case setServiceTimeoutRx.MatchString(line):
			continue
		case strings.HasPrefix(line, "set service"):
			panic(line)

		case setAddressRx.MatchString(line):
			var ip net.IPNet

			parts := setAddressRx.FindAllStringSubmatch(line, -1)
			if parts[0][4] == "" {
				// Resolve
				ipaddr, err := net.ResolveIPAddr("ip", parts[0][3])
				if err != nil {
					_, _ = fmt.Fprint(os.Stderr, err.Error(), "\n")
					continue
				}
				ip = net.IPNet{
					IP:   ipaddr.IP,
					Mask: net.IPMask(net.IPv4bcast),
				}
			} else {
				ip = net.IPNet{
					IP:   net.ParseIP(parts[0][3]),
					Mask: net.IPMask(net.ParseIP(parts[0][4])),
				}
			}
			if ip.IP == nil || ip.Mask == nil {
				panic(parts)
			}

			objects.Add(parts[0][1], parts[0][2], &ip)
		case strings.HasPrefix(line, "set address"):
			panic(line)

		case setGroupAddressRx.MatchString(line):
			parts := setGroupAddressRx.FindAllStringSubmatch(line, -1)
			objects.AddToGroup(parts[0][1], parts[0][2], parts[0][3])
		case setGroupAddressCreateRx.MatchString(line):
			// Skip group creation
			continue
		case strings.HasPrefix(line, "set group address"):
			panic(line)

		case setPolicyCreateRx.MatchString(line):
			// Create policy
			parts := setPolicyCreateRx.FindAllStringSubmatch(line, -1)
			id, err := strconv.Atoi(parts[0][1])
			if err != nil {
				panic(err)
			}

			var natPort int
			if parts[0][13] != "" {
				natPort, err = strconv.Atoi(parts[0][13])
				if err != nil {
					panic(err)
				}
			}

			p := Policy{
				ID:           id,
				Name:         parts[0][3],
				From:         parts[0][4],
				To:           parts[0][5],
				Sources:      []string{parts[0][6]},
				Destinations: []string{parts[0][7]},
				Services:     []string{parts[0][8]},
				NAT:          parts[0][9],
				NATAddress:   parts[0][11],
				NATPort:      natPort,
				Action:       parts[0][14],
				Log:          parts[0][15] == "log",
				LogInit:      false,
				Disabled:     false,
			}

			if !p.IsValid() {
				_ = json.NewEncoder(os.Stdout).Encode(p)
				panic("not valid")
			}

			policies = append(policies, p)
		case setPolicyRx.MatchString(line):
			parts := setPolicyRx.FindAllStringSubmatch(line, -1)
			if len(parts) == 0 || len(parts[0]) < 2 {
				_ = json.NewEncoder(os.Stdout).Encode(parts)
				panic(line)
			}
			id, err := strconv.Atoi(parts[0][1])
			if err != nil {
				panic(err)
			}

			var policy = -1
			for idx, p := range policies {
				if p.ID == id {
					policy = idx
				}
			}

			if policy == -1 {
				_ = json.NewEncoder(os.Stdout).Encode(id)
				_ = json.NewEncoder(os.Stdout).Encode(policies)
				panic("policy not found: " + line)
			}

			for scanner.Scan() {
				line = scanner.Text()

				if line == "exit" {
					break
				}

				switch {
				case setPolicyServiceRx.MatchString(line):
					parts := setPolicyServiceRx.FindAllStringSubmatch(line, -1)
					if len(parts) == 0 || len(parts[0]) < 2 {
						_ = json.NewEncoder(os.Stdout).Encode(parts)
						panic(line)
					}

					switch parts[0][1] {
					case "service":
						policies[policy].Services = append(policies[policy].Services, parts[0][2])
					case "src-address":
						policies[policy].Sources = append(policies[policy].Sources, parts[0][2])
					case "dst-address":
						policies[policy].Destinations = append(policies[policy].Destinations, parts[0][2])
					default:
						panic(line)
					}
				case setLogOptionsRx.MatchString(line):
					parts := setLogOptionsRx.FindAllStringSubmatch(line, -1)

					if parts[0][1] == "session-init" {
						policies[policy].LogInit = true
					} else {
						panic(line)
					}
				default:
					panic(line)
				}
			}

			// Update policy
		case setPolicyFlagsRx.MatchString(line):
			parts := setPolicyFlagsRx.FindAllStringSubmatch(line, -1)
			if len(parts) == 0 || len(parts[0]) < 2 {
				_ = json.NewEncoder(os.Stdout).Encode(parts)
				panic(line)
			}
			id, err := strconv.Atoi(parts[0][1])
			if err != nil {
				panic(err)
			}

			var policy = -1
			for idx, p := range policies {
				if p.ID == id {
					policy = idx
				}
			}

			if policy == -1 {
				_ = json.NewEncoder(os.Stdout).Encode(id)
				_ = json.NewEncoder(os.Stdout).Encode(policies)
				panic("policy not found: " + line)
			}

			switch parts[0][2] {
			case "disable":
				policies[policy].Disabled = true
			case "application":
				policies[policy].Application = parts[0][4]
			default:
				panic(line)
			}

		case strings.HasPrefix(line, "set policy id"):
			panic(line)
		}
	}

	return policies, objects, services
}

func mustInt(s string) int {
	ret, err := strconv.Atoi(s)
	if err != nil {
		panic(err)
	}
	return ret
}

func defaultServices() Services {
	var services = make(Services)

	services["ANY"] = ServiceList{Service{
		Protocol:     "",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 0,
		DstPortEnd:   65535,
	}}
	services["HTTP"] = ServiceList{Service{
		Protocol:     "tcp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 80,
		DstPortEnd:   80,
	}}
	services["HTTPS"] = ServiceList{Service{
		Protocol:     "tcp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 443,
		DstPortEnd:   443,
	}}
	services["TELNET"] = ServiceList{Service{
		Protocol:     "tcp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 23,
		DstPortEnd:   23,
	}}
	services["SSH"] = ServiceList{Service{
		Protocol:     "tcp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 22,
		DstPortEnd:   22,
	}}
	services["SYSLOG"] = ServiceList{Service{
		Protocol:     "udp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 514,
		DstPortEnd:   514,
	}}
	services["FTP"] = ServiceList{Service{
		Protocol:     "tcp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 20,
		DstPortEnd:   21,
	}}
	services["CIFS"] = ServiceList{Service{
		Protocol:     "udp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 137,
		DstPortEnd:   138,
	}, Service{
		Protocol:     "tcp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 139,
		DstPortEnd:   139,
	}, Service{
		Protocol:     "tcp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 445,
		DstPortEnd:   445,
	}}
	services["MS-SQL"] = ServiceList{Service{
		Protocol:     "tcp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 1433,
		DstPortEnd:   1433,
	}, Service{
		Protocol:     "udp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 1434,
		DstPortEnd:   1434,
	}}
	services["SQL Monitor"] = ServiceList{Service{
		Protocol:     "udp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 1434,
		DstPortEnd:   1434,
	}}
	services["RADIUS"] = ServiceList{Service{
		Protocol:     "udp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 1812,
		DstPortEnd:   1813,
	}}
	services["VNC"] = ServiceList{Service{
		Protocol:     "tcp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 5900,
		DstPortEnd:   5900,
	}}
	services["PING"] = ServiceList{Service{
		Protocol: "icmp",
		IcmpType: 8,
	}}
	services["MAIL"] = ServiceList{Service{
		Protocol:     "tcp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 25,
		DstPortEnd:   25,
	}, Service{
		Protocol:     "tcp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 465,
		DstPortEnd:   465,
	}, Service{
		Protocol:     "tcp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 587,
		DstPortEnd:   587,
	}}
	services["H.323"] = ServiceList{Service{
		Protocol:     "udp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 1719,
		DstPortEnd:   1719,
	}, Service{
		Protocol:     "tcp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 1720,
		DstPortEnd:   1720,
	}, Service{
		Protocol:     "tcp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 1731,
		DstPortEnd:   1731,
	}, Service{
		Protocol:     "tcp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 1024,
		DstPortEnd:   65535,
	}}
	services["SCCP"] = ServiceList{Service{
		Protocol:     "tcp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 2000,
		DstPortEnd:   2000,
	}}
	services["SIP"] = ServiceList{Service{
		Protocol:     "tcp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 5060,
		DstPortEnd:   5061,
	}, Service{
		Protocol:     "udp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 5060,
		DstPortEnd:   5061,
	}}
	services["TFTP"] = ServiceList{Service{
		Protocol:     "udp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 69,
		DstPortEnd:   69,
	}, Service{
		Protocol:     "udp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 1024,
		DstPortEnd:   65535,
	}}
	services["SMTP"] = ServiceList{Service{
		Protocol:     "tcp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 25,
		DstPortEnd:   25,
	}, Service{
		Protocol:     "tcp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 465,
		DstPortEnd:   465,
	}, Service{
		Protocol:     "tcp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 587,
		DstPortEnd:   587,
	}}
	services["PPTP"] = ServiceList{Service{
		Protocol:     "tcp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 1723,
		DstPortEnd:   1723,
	}, Service{
		Protocol: "47",
	}}
	services["HTTP-EXT"] = ServiceList{Service{
		Protocol:     "tcp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 8080,
		DstPortEnd:   8080,
	}}
	services["ICMP-ANY"] = ServiceList{Service{
		Protocol: "icmp",
	}}
	services["UDP-ANY"] = ServiceList{Service{
		Protocol:     "udp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 0,
		DstPortEnd:   65535,
	}}
	services["TCP-ANY"] = ServiceList{Service{
		Protocol:     "tcp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 0,
		DstPortEnd:   65535,
	}}
	services["DHCP-Relay"] = ServiceList{Service{
		Protocol:     "udp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 67,
		DstPortEnd:   68,
	}}
	services["DHCP-Relay"] = ServiceList{Service{
		Protocol:     "udp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 67,
		DstPortEnd:   68,
	}}
	services["NBDS"] = ServiceList{Service{
		Protocol:     "udp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 137,
		DstPortEnd:   137,
	}}
	services["NBNAME"] = ServiceList{Service{
		Protocol:     "udp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 138,
		DstPortEnd:   138,
	}}
	services["SMB"] = ServiceList{Service{
		Protocol:     "tcp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 445,
		DstPortEnd:   445,
	}}
	services["SNMP"] = ServiceList{Service{
		Protocol:     "udp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 161,
		DstPortEnd:   161,
	}}
	services["NFS"] = ServiceList{Service{
		Protocol:     "tcp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 111,
		DstPortEnd:   111,
	}, Service{
		Protocol:     "udp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 111,
		DstPortEnd:   111,
	}, Service{
		Protocol:     "tcp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 2049,
		DstPortEnd:   2049,
	}, Service{
		Protocol:     "udp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 2049,
		DstPortEnd:   2049,
	}}
	services["IMAP"] = ServiceList{Service{
		Protocol:     "tcp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 143,
		DstPortEnd:   143,
	}}
	services["POP3"] = ServiceList{Service{
		Protocol:     "tcp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 110,
		DstPortEnd:   110,
	}}
	services["DNS"] = ServiceList{Service{
		Protocol:     "tcp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 53,
		DstPortEnd:   53,
	}, Service{
		Protocol:     "udp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 53,
		DstPortEnd:   53,
	}}
	services["LDAP"] = ServiceList{Service{
		Protocol:     "tcp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 389,
		DstPortEnd:   389,
	}}
	services["NTP"] = ServiceList{Service{
		Protocol:     "udp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 123,
		DstPortEnd:   123,
	}}
	services["MS-AD-BR"] = ServiceList{}
	services["MS-AD-DRSUAPI"] = ServiceList{}
	services["MS-AD-DSROLE"] = ServiceList{}
	services["MS-AD-DSSETUP"] = ServiceList{}
	services["MS-RPC-ANY"] = ServiceList{}
	services["MS-RPC-EPM"] = ServiceList{}
	services["MS-WIN-DNS"] = ServiceList{}
	services["MS-WINS"] = ServiceList{}
	services["MS-AD"] = ServiceList{}
	services["WHOIS"] = ServiceList{}
	services["MS-NETLOGON"] = ServiceList{Service{
		Protocol:     "udp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 137,
		DstPortEnd:   138,
	}, Service{
		Protocol:     "tcp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 139,
		DstPortEnd:   139,
	}, Service{
		Protocol:     "tcp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 445,
		DstPortEnd:   445,
	}, Service{
		Protocol:     "tcp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 1024,
		DstPortEnd:   5000,
	}, Service{
		Protocol:     "tcp",
		SrcPortStart: 0,
		SrcPortEnd:   65535,
		DstPortStart: 49152,
		DstPortEnd:   65535,
	}}
	return services
}
