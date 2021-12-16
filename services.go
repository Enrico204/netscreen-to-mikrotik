package main

type Service struct {
	Protocol     string
	IcmpType     int
	SrcPortStart int
	SrcPortEnd   int
	DstPortStart int
	DstPortEnd   int
}

type Services map[string]ServiceList

type ServiceList []Service

func (s Services) Add(name string, service Service) {
	if _, ok := s[name]; !ok {
		s[name] = []Service{service}
	} else {
		s[name] = append(s[name], service)
	}
}

func (sl ServiceList) AllProtocols() []string {
	var protos = make(map[string]int)
	for _, s := range sl {
		protos[s.Protocol] = 1
	}
	var ret = make([]string, 0, len(protos))
	for proto := range protos {
		ret = append(ret, proto)
	}
	return ret
}
