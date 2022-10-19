//go:build linux

package stun

import (
	"log"
	"strings"
	"sync"

	"github.com/coreos/go-iptables/iptables"
)

var (
	IptClient *iptables.IPTables
	Lock      sync.Mutex
)

func iptablesNew() {
	log.Println("IptablesNew")
	var err error
	IptClient, err = iptables.New()
	if err != nil {
		log.Println("Iptables New failed:", err)
	}
}

func IPTablesAppendUnique(tableName, chainName string, args ...string) error {
	if IptClient == nil {
		iptablesNew()
	}

	Lock.Lock()
	defer Lock.Unlock()

	log.Println("IptablesAppendUnique:", tableName, chainName, strings.Join(args, " "))
	exists, err := IptClient.Exists(tableName, chainName, args...)
	if err != nil {
		log.Println("Iptables Exists failed:", err)
		return err
	}

	if !exists {
		err = IptClient.Append(tableName, chainName, args...)
		if err != nil {
			log.Println("Iptables Append failed:", err)
			return err
		}
	} else {
		log.Println("IptablesAppendUnique: duplicate!")
	}

	return nil
}

func IPTablesDelete(tableName, chainName string, args ...string) error {
	if IptClient == nil {
		iptablesNew()
	}

	Lock.Lock()
	defer Lock.Unlock()

	log.Println("IptablesDeleteIfExists:", tableName, chainName, strings.Join(args, " "))
	exists, err := IptClient.Exists(tableName, chainName, args...)
	if err != nil {
		log.Println("Iptables Exists failed:", err)
	}

	if err == nil && exists {
		err = IptClient.Delete(tableName, chainName, args...)
	}

	return err
}

func IPTablesNewChain(tableName, chainName, subChainName string) error {

    if IptClient == nil {
        iptablesNew()
    }

    log.Println("IptablesNewChain:", tableName, chainName, subChainName)
    err := IptClient.NewChain(tableName, subChainName)
    if err != nil {
        log.Println("Iptables NewChain failed:", err)
    }

    err = IPTablesAppendUnique(tableName, chainName, "-j", subChainName)
    if err != nil {
        log.Println("Iptables AppendUnique failed:", err)
    }

    return nil
}

func IPTablesClearChain(tableName, chainName string) error {

	if IptClient == nil {
		iptablesNew()
	}

	log.Println("IptablesClearChain", tableName, chainName)
	err := IptClient.ClearChain(tableName, chainName)
	if err != nil {
		log.Println("Iptables ClearChain failed:", err)
		return err
	}

	return nil
}

//iptables -t mangle -I VPR_PREROUTING -p udp -m u32 --u32 "32=0x2112A442" -j MARK --set-xmark 0x60000/0xff0000
//ip rule add from all fwmark 0x60000 lookup 206
//Ip route add default via <vpn gateway ip> dev <vpn gateway device> table 206

//sudo iptables -A PREROUTING -i eth0 -p udp --dport 443 -m u32 --u32 "32=0x2112A442" -j REDIRECT --to-port 3478
//iptables -t nat -A POSTROUTING -s 192.168.123.0/24 ! -o tun0 -j MASQUERADE
//iptables -t filter -A FORWARD -i tun0 ! -o tun0 -j ACCEPT
//iptables -t filter -A FORWARD -o tun0 -j ACCEPT

// srcip = "192.168.123.0/24"
// tap = "tun0"
// QuiueId = x
// SpoofIP = "23.18.987.0"