package dnsfilter

import (
	"bufio"
	"io"
	"io/ioutil"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/AdguardTeam/AdGuardHome/util"
	"github.com/AdguardTeam/golibs/log"
	"github.com/fsnotify/fsnotify"
)

// AutoHosts - automatic DNS records
type AutoHosts struct {
	lock       sync.Mutex          // serialize access to table
	table      map[string][]net.IP // 'hostname -> IP' table
	hostsFn    string              // path to the main hosts-file
	hostsDirs  []string            // paths to OS-specific directories with hosts-files
	watcher    *fsnotify.Watcher   // file and directory watcher object
	updateChan chan bool           // signal for 'update' goroutine
}

// Init - initialize
func (a *AutoHosts) Init() {
	a.table = make(map[string][]net.IP)
	a.updateChan = make(chan bool, 2)

	a.hostsFn = "/etc/hosts"
	if runtime.GOOS == "windows" {
		a.hostsFn = os.ExpandEnv("$SystemRoot\\system32\\drivers\\etc\\hosts")
	}

	if util.IsOpenWrt() {
		a.hostsDirs = append(a.hostsDirs, "/tmp/hosts") // OpenWRT: "/tmp/hosts/dhcp.cfg01411c"
	}

	go a.update()
	a.updateChan <- true

	var err error
	a.watcher, err = fsnotify.NewWatcher()
	if err != nil {
		log.Error("AutoHosts: %s", err)
	}

	go a.watcherLoop()

	err = a.watcher.Add(a.hostsFn)
	if err != nil {
		log.Error("AutoHosts: %s", err)
	}

	for _, dir := range a.hostsDirs {
		err = a.watcher.Add(dir)
		if err != nil {
			log.Error("AutoHosts: %s", err)
		}
	}
}

// Close - close module
func (a *AutoHosts) Close() {
	a.updateChan <- false
	a.watcher.Close()
}

// Read IP-hostname pairs from file
// Multiple hostnames per line (per one IP) is supported.
func (a *AutoHosts) load(table map[string][]net.IP, fn string) {
	f, err := os.Open(fn)
	if err != nil {
		log.Error("AutoHosts: %s", err)
		return
	}
	defer f.Close()
	r := bufio.NewReader(f)
	log.Debug("AutoHosts: loading hosts from file %s", fn)

	for {
		line, err := r.ReadString('\n')
		if err == io.EOF {
			break
		} else if err != nil {
			log.Error("AutoHosts: %s", err)
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
			log.Debug("AutoHosts: added %s -> %s", ip, host)
		}
	}
}

// Receive notifications from fsnotify package
func (a *AutoHosts) watcherLoop() {
	for {
		select {

		case event, ok := <-a.watcher.Events:
			if !ok {
				return
			}
			if event.Op&fsnotify.Write == fsnotify.Write {
				log.Debug("AutoHosts: modified: %s", event.Name)
				select {
				case a.updateChan <- true:
					// sent a signal to 'update' goroutine
				default:
					// queue is full
				}
			}

		case err, ok := <-a.watcher.Errors:
			if !ok {
				return
			}
			log.Error("AutoHosts: %s", err)
		}
	}
}

// Read static hosts from system files
func (a *AutoHosts) update() {
	for {
		select {
		case ok := <-a.updateChan:
			if !ok {
				return
			}

			table := make(map[string][]net.IP)

			a.load(table, a.hostsFn)

			for _, dir := range a.hostsDirs {
				fis, err := ioutil.ReadDir(dir)
				if err != nil {
					if !os.IsNotExist(err) {
						log.Error("AutoHosts: Opening directory: %s: %s", dir, err)
					}
					continue
				}

				for _, fi := range fis {
					a.load(table, dir+"/"+fi.Name())
				}
			}

			a.lock.Lock()
			a.table = table
			a.lock.Unlock()
		}
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
