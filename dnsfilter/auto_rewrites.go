package dnsfilter

import (
	"bufio"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardHome/util"
	"github.com/AdguardTeam/golibs/log"
)

// AutoRewrites - automatic DNS records
type AutoRewrites struct {
	lock  sync.Mutex
	table map[string][]net.IP
}

// Init - initialize
func (a *AutoRewrites) Init() {
	a.table = make(map[string][]net.IP)
	go a.periodicUpdate()
}

func (a *AutoRewrites) load(table map[string][]net.IP, fn string) {
	f, err := os.Open(fn)
	if err != nil {
		log.Error("Auto-rewrites: %s", err)
		return
	}
	defer f.Close()
	r := bufio.NewReader(f)

	for {
		line, err := r.ReadString('\n')
		if err == io.EOF {
			break
		} else if err != nil {
			log.Error("Auto-rewrites: %s", err)
			return
		}
		line = strings.TrimSpace(line)

		ip := util.SplitNext(&line, ' ')
		ipAddr := net.ParseIP(ip)
		if ipAddr == nil {
			continue
		}
		for {
			host := util.SplitNext(&line, ' ')
			if len(host) == 0 {
				break
			}
			ips, ok := table[host]
			if ok {
				ips = append(ips, ipAddr)
			} else {
				table[host] = []net.IP{ipAddr}
			}
			log.Debug("Auto-rewrites: added %s -> %s", ip, host)
		}
	}
}

func (a *AutoRewrites) periodicUpdate() {
	for {
		table := make(map[string][]net.IP)
		a.load(table, "/etc/hosts")

		a.lock.Lock()
		a.table = table
		a.lock.Unlock()

		time.Sleep(1 * time.Hour)
	}
}

func (a *AutoRewrites) process(host string) []net.IP {
	a.lock.Lock()
	ips, _ := a.table[host]
	ipsCopy := make([]net.IP, len(ips))
	copy(ipsCopy, ips)
	a.lock.Unlock()
	return ipsCopy
}
