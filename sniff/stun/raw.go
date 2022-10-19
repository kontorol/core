//go:build linux

package stun

import (
	"errors"
	"fmt"
	"net"
	"os"

	pkt "github.com/mdlayher/packet"
	"golang.org/x/sys/unix"
)

type RAW struct {
	Conn       net.PacketConn
	Frame      FrameOptions
	PacketByte []byte
}

// NewRawUDPConn returns a UDP connection bound to the interface and port
// given based on a raw packet socket. All packets are broadcasted.
//
// The interface can be completely unconfigured.
// set HWD SRC Addr , Raw Conn , SetPromiscuous , setMark
func (s Spoof) NewRawUDPConn() (*Spoof,error) {

	ifc, err := checkInterface(s.md.intf)
	if err != nil {
		return nil,err
	}
	s.raw.Frame.HWD.Src = ifc.HardwareAddr

	rawConn, err := pkt.Listen(ifc, pkt.Raw, unix.ETH_P_ALL, nil)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return nil,fmt.Errorf("skipping, permission denied (try setting CAP_NET_RAW capability): %v", err)
		}
		return nil,fmt.Errorf("failed to listen: %v", err)
	}

	// err = rawConn.SetPromiscuous(promiscuous)
	// if err != nil {
	// 	return nil, err
	// }

	Mark := s.md.mark
	if Mark != 0 {
		sc, err := rawConn.SyscallConn()
		err = sc.Control(func(fd uintptr) {

			if err = setMark(fd, Mark); err != nil {
				err = fmt.Errorf("set mark: %v", err)
			}

		})
		if err != nil {
			return nil,err
		}
	}

	s.raw.Conn = rawConn
	return &s,nil
}

func setMark(fd uintptr, mark int) error {
	if mark == 0 {
		return nil
	}
	return unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, mark)
}

func checkInterface(IfceName string) (*net.Interface, error) {

	ifc, err := net.InterfaceByName(IfceName)
	if err != nil {
		return nil, err
	}
	ok := true &&
		// Look for an Ethernet interface.
		len(ifc.HardwareAddr) == 6 &&
		// Look for up, multicast, broadcast.
		ifc.Flags&(net.FlagUp|net.FlagMulticast|net.FlagBroadcast) != 0

	if !ok {
		return nil, fmt.Errorf("interface no support raw connection")
	}

	return ifc, nil
}
