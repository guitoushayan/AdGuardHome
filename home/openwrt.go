package home

import (
	"fmt"
	"net"
	"strconv"

	"github.com/AdguardTeam/AdGuardHome/util"
)

type openwrtConfig struct {
	// network:
	netmask string
	ipaddr  string

	// dhcp:
	dhcpStart     string
	dhcpLimit     string
	dhcpLeasetime string

	// resolv.conf:
	nameservers []string

	// yaml.dhcp:
	iface      string
	gwIP       string
	snMask     string
	rangeStart net.IP
	rangeEnd   net.IP
	leaseDur   uint32

	// yaml.dns.bootstrap_dns:
	bsDNS []string
}

// Parse command line: "option name 'value'"
func parseCmd(line string) (string, string, string) {
	word1 := util.SplitNext(&line, ' ')
	word2 := util.SplitNext(&line, ' ')
	word3 := util.SplitNext(&line, ' ')
	if len(word3) > 2 && word3[0] == '\'' && word3[len(word3)-1] == '\'' {
		// 'value' -> value
		word3 = word3[1:]
		word3 = word3[:len(word3)-1]
	}
	return word1, word2, word3
}

// Parse system configuration data
func (oc *openwrtConfig) readConf(data []byte, section string, iface string) {
	lines := string(data)
	state := 0
	for len(lines) != 0 {
		line := util.SplitNext(&lines, '\n')
		if len(line) == 0 {
			if state == 2 {
				return
			}
			state = 0
		}

		word1, word2, word3 := parseCmd(line)

		switch state {
		case 0:
			if word1 == "config" {
				state = 1
				if word2 == section && word3 == iface {
					// found the needed section
					if word2 == "interface" {
						state = 2 // found the needed interface
					} else if word2 == "dhcp" {
						state = 3
					}
				}
			}

		case 1:
			// not interested
			break

		case 2:
			if word1 != "option" {
				break
			}
			switch word2 {
			case "netmask":
				oc.netmask = word3
			case "ipaddr":
				oc.ipaddr = word3
			}

		case 3:
			if word1 != "option" {
				break
			}
			switch word2 {
			case "start":
				oc.dhcpStart = word3
			case "limit":
				oc.dhcpLimit = word3
			case "leasetime":
				oc.dhcpLeasetime = word3
			}
		}
	}
}

// Parse "/etc/resolv.conf" data
func (oc *openwrtConfig) readResolvConf(data []byte) {
	lines := string(data)

	for len(lines) != 0 {
		line := util.SplitNext(&lines, '\n')
		key := util.SplitNext(&line, ' ')
		if key == "nameserver" {
			val := util.SplitNext(&line, ' ')
			oc.nameservers = append(oc.nameservers, val)
		}
	}
}

// Convert system config parameters to the format suitable by our yaml config
func (oc *openwrtConfig) prepareOutput() error {
	oc.iface = "br-lan"

	ipAddr := net.ParseIP(oc.ipaddr)
	if ipAddr == nil || ipAddr.To4() == nil {
		return fmt.Errorf("Invalid IP: %s", oc.ipaddr)
	}
	oc.gwIP = oc.ipaddr

	ip := net.ParseIP(oc.netmask)
	if ip == nil || ip.To4() == nil {
		return fmt.Errorf("Invalid IP: %s", oc.netmask)
	}
	oc.snMask = oc.netmask

	nStart, err := strconv.Atoi(oc.dhcpStart)
	if err != nil {
		return fmt.Errorf("Invalid 'start': %s", oc.dhcpStart)
	}
	oc.rangeStart = make(net.IP, 4)
	copy(oc.rangeStart, ipAddr.To4())
	oc.rangeStart[3] = byte(nStart)

	nLim, err := strconv.Atoi(oc.dhcpLimit)
	if err != nil {
		return fmt.Errorf("Invalid 'start': %s", oc.dhcpLimit)
	}
	oc.rangeEnd = make(net.IP, 4)
	copy(oc.rangeEnd, ipAddr.To4())
	n := nStart + nLim - 1
	if n <= 0 || n > 255 {
		return fmt.Errorf("Invalid 'start' or 'limit': %s/%s", oc.dhcpStart, oc.dhcpLimit)
	}
	oc.rangeEnd[3] = byte(n)

	if len(oc.dhcpLeasetime) == 0 || oc.dhcpLeasetime[len(oc.dhcpLeasetime)-1] != 'h' {
		return fmt.Errorf("Invalid leasetime: %s", oc.dhcpLeasetime)
	}
	n, err = strconv.Atoi(oc.dhcpLeasetime[:len(oc.dhcpLeasetime)-1])
	if err != nil {
		return fmt.Errorf("Invalid leasetime: %s", oc.dhcpLeasetime)
	}
	oc.leaseDur = uint32(n) * 60 * 60

	for _, s := range oc.nameservers {
		if net.ParseIP(s) == nil {
			continue
		}
		oc.bsDNS = append(oc.bsDNS, s)
	}
	return nil
}
