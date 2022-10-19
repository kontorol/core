//go:build linux

package stun

import (
	"fmt"
	"net"

	"github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/core/metadata/util"
)

const (
	mdKeyInterface = "interface" //string
	mdKeySoMark    = "so_mark" //int
	mdKeyStun      = "stun" //string
	mdKeyStunOnly  = "stunonly" //bool
	mdKeyNFQ       = "nfq" //bool
	mdKeyNFQID     = "nfqid" // uint16 user nfq assigned id
	mdKeySMAC      = "smac" //string
	mdKeyDMAC      = "dmac" //string
)

func parseMetadata(md metadata.Metadata,mark int) (*Spoof, error) {

	var s Spoof
	var vv net.IP

	// MD
	if v := mdutil.GetString(md, mdKeyStun); v != "" {
		vv = net.ParseIP(v).To4()
	} else {
		return nil,nil
	}

	if v := mdutil.GetString(md, mdKeyInterface); v != "" {
		s.md.intf = v
	}

	s.md.stunOnly = mdutil.GetBool(md, mdKeyStunOnly)

	if mark > 0 {
		s.md.mark = mark
	}

	s.md.isNFQ = mdutil.GetBool(md, mdKeyNFQ)
	if s.md.isNFQ {
		s.md.spoofIP = vv
		if v := mdutil.GetInt(md, mdKeyNFQID); v > 0 {
			s.md.NFQID = uint16(v)
		} else if s.md.mark > 0 {
			s.md.NFQID = uint16(s.md.mark)
		} else {
			return nil, fmt.Errorf("NFQ: so_mark must be set and > 0")
		}
	} else {
		s.raw.Frame.IP.Src = vv
		// Get and Set User SrcMac if any else later use output Interface Mac addr by default
		if spfsHw, err := net.ParseMAC(mdutil.GetString(md, mdKeySMAC)); err == nil {
			s.raw.Frame.HWD.Src = spfsHw
		}

		// Set DstMac to Broadcast if "dmac" = br
		if dsmac := mdutil.GetString(md, mdKeyDMAC); dsmac != "" {
			spfdHw, err := net.ParseMAC(dsmac)
			if err != nil {
				return nil,fmt.Errorf("RAW: parse DstMAC error: %s",err)
			}
			s.raw.Frame.HWD.Dst = spfdHw
		} //else {
		// spoof.Frame.HWD.Dst = arp()
		// }
	}
	s.SpoofEnable = true

	return &s, nil

}
