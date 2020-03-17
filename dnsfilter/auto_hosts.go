package dnsfilter

import (
	"bufio"
	"io"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardHome/util"
	"github.com/AdguardTeam/golibs/log"
)

// AutoHosts - automatic DNS records
type AutoHosts struct {
	lock  sync.Mutex
	table map[string][]net.IP
}

// Init - initialize
func (a *AutoHosts) Init() {
	a.table = make(map[string][]net.IP)
	go a.periodicUpdate()
}

// Read IP-hostname pairs from file
// Multiple hostnames per line (per one IP) is supported.
func (a *AutoHosts) load(table map[string][]net.IP, fn string) {
	f, err := os.Open(fn)
	if err != nil {
		log.Error("Auto-rewrites: %s", err)
		return
	}
	defer f.Close()
	r := bufio.NewReader(f)
	log.Debug("Loading hosts from file %s", fn)

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
				table[host] = ips
			} else {
				table[host] = []net.IP{ipAddr}
			}
			log.Debug("Auto-rewrites: added %s -> %s", ip, host)
		}
	}
}

// Periodically re-read static hosts from system files
func (a *AutoHosts) periodicUpdate() {
	for {
		table := make(map[string][]net.IP)
		a.load(table, "/etc/hosts")

		dirs := []string{
			"/tmp/hosts", // OpenWRT: "/tmp/hosts/dhcp.cfg01411c"
		}
		for _, dir := range dirs {
			fis, err := ioutil.ReadDir(dir)
			if err != nil {
				if !os.IsNotExist(err) {
					log.Error("Opening directory: %s: %s", dir, err)
				}
				continue
			}

			for _, fi := range fis {
				a.load(table, fi.Name())
			}
		}

		a.lock.Lock()
		a.table = table
		a.lock.Unlock()

		time.Sleep(1 * time.Hour)
	}
}

// Get the list of IP addresses for the hostname
func (a *AutoHosts) process(host string) []net.IP {
	a.lock.Lock()
	ips, _ := a.table[host]
	ipsCopy := make([]net.IP, len(ips))
	copy(ipsCopy, ips)
	a.lock.Unlock()
	return ipsCopy
}
