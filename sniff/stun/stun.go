//go:build linux

package stun

import (
	"bytes"
	"fmt"
	"net"
	"strconv"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/metadata"
)

type StunMetadata struct {
	mark     int
	spoofIP  net.IP
	stunOnly bool
	NFQID    uint16
	isNFQ    bool
	intf     string
}

type Spoof struct {
	md          StunMetadata
	queue       NFQUEUE
	raw         RAW
	stun        packet
	SpoofEnable bool
	logger      logger.Logger
}

func (s Spoof) SetRawSrcByte(b []byte) Spoof {
	s.raw.PacketByte = b
	return s
}


func (s Spoof) SetLogger(log logger.Logger) *Spoof {
	s.logger = log
	return &s
}

func EmptyStun() (*Spoof) {
	return &Spoof{}
}

func InitStun(md metadata.Metadata, mark int) (*Spoof, error) {
	spf, err := parseMetadata(md, mark)
	if err != nil {
		return nil, err
	}
	if spf == nil{
		spf = EmptyStun()
	}

	if spf.SpoofEnable {

		if spf.md.isNFQ {
			if err := ipTablesAppend(spf.md.mark, spf.md.NFQID); err != nil {
				return nil, err
			}
			spf.queue = NewNFQ(spf.md.NFQID)
		} else {
			if spf, err = spf.NewRawUDPConn(); err != nil {
				return nil, err
			}

		}
		return spf, nil
	} else {
		return spf, nil
	}

}

func (s Spoof) IsNFQ() bool {
	return s.md.isNFQ
}

func (s Spoof) Spoof() (bool, error) {
	if !s.md.isNFQ {

		if pkt, err := IsStunReq(s.raw.PacketByte, s); err == nil && len(pkt.Bytes()) > 0 {

			s.stun = *pkt
			s.raw.Frame.IP.isV4 = true
			pkg2send, err := s.raw.Frame.Payload2Pkg(s.raw.PacketByte)
			if err != nil {
				return true, err
			}

			err = sendStun(s.raw.Conn, pkg2send)

			if s.logger != nil {
				s.logger.Tracef("%s:%s >>> %s:%s data: %d",
					s.raw.Frame.IP.Src.String(), s.raw.Frame.UDP.Src, s.raw.Frame.IP.Dst.String(), s.raw.Frame.UDP.Dst, s.stun.PacketLength())
			}

			return true, err

		}
		if s.md.stunOnly {
			return true, nil
		}
	}
	return false, nil

}

func (s Spoof) Close() error {
	return ipTDelete(s.md.mark, s.md.NFQID)
}

func ipTablesAppend(mark int, QueueId uint16) error {

	err := IPTablesNewChain("mangle", "POSTROUTING", "DARK_MANGLE_POSTROUTING")
	if err != nil {
		// log.Println("Iptables NewChain DARK_MANGLE_POSTROUTING failed:", err)
		return err
	}

	err = IPTablesAppendUnique("mangle", "DARK_MANGLE_POSTROUTING", "-p", "udp", "-m", "mark", "--mark", strconv.Itoa(mark), "-m", "u32", "--u32", "32=0x2112A442", "-j", "NFQUEUE", "--queue-num", strconv.Itoa(int(QueueId)))
	if err != nil {
		// log.Println("Iptables Append NetFilterQueue failed:", err)
		return err
	}

	return nil
}

func ipTDelete(mark int, QueueId uint16) error {
	if QueueId == uint16(0) {
		QueueId = uint16(mark)
	}

	err := IPTablesDelete("mangle", "DARK_MANGLE_POSTROUTING", "-p", "udp", "-m", "mark", "--mark", strconv.Itoa(mark), "-m", "u32", "--u32", "32=0x2112A442", "-j", "NFQUEUE", "--queue-num", strconv.Itoa(int(QueueId)))
	if err != nil {
		// log.Println("Iptables Append NetFilterQueue failed:", err)
		return err
	}

	return nil
}

func IsStunResCorrect(pkt *packet, spoof Spoof, pc2LocalAddr, raddr string, withRes bool) (*response, error) {

	// If transId mismatches, keep reading until get a
	// matched packet or timeout.
	if !bytes.Equal(spoof.stun.transID, pkt.transID) {
		return nil, fmt.Errorf("stun transID not equal")
	}

	if withRes {

		resp := newResponse(pkt, pc2LocalAddr)
		resp.serverAddr = newHostFromStr(raddr)

		// if resp.mappedAddr.IP() != spoof.Frame.IP.Src.String() {
		// 	return nil, fmt.Errorf("stun transID not equal")
		// }

		return resp, nil
	}

	return nil, nil

}

func IsStunReq(packetBytes []byte, spoof Spoof) (*packet, error) {

	if !spoof.SpoofEnable {
		return nil, fmt.Errorf("stun not enabled")
	}

	if spoof.raw.Conn == nil {
		return nil, fmt.Errorf("error raw conn is nil")
	}

	return IsStun(packetBytes)

}

func (v *packet) Bytes() []byte {
	return v.bytes()
}

func (v *packet) PacketLength() uint16 {
	return v.length
}

func (s Spoof) SetAddr(raddr, pc2local string) (*Spoof, error) {
	RAddr, err := net.ResolveUDPAddr("udp", raddr)
	if err != nil {
		return nil, err
	}

	sip, err := net.ResolveUDPAddr("udp", pc2local)
	if err != nil {
		return nil, err
	}

	s.raw.Frame.UDP.Src = sip.AddrPort().Port()

	s.raw.Frame.IP.Dst = RAddr.IP.To4()
	s.raw.Frame.UDP.Dst = RAddr.AddrPort().Port()
	return &s, nil
}
