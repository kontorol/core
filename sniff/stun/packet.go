//go:build linux

package stun

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	pkt "github.com/mdlayher/packet"
)

type HWD struct {
	Src, Dst net.HardwareAddr
}

type IP struct {
	isV4     bool
	Src, Dst net.IP
}

type UDP struct {
	Src, Dst uint16
}

type FrameOptions struct {
	HWD HWD
	IP  IP
	UDP UDP
}
type serializableNetworkLayer interface {
	gopacket.NetworkLayer
	SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error
}

func sendStun(Conn net.PacketConn, pkg2send []byte) error {
	length, err := Conn.WriteTo(pkg2send, &pkt.Addr{HardwareAddr: BroadcastMac})

	if err != nil || length != len(pkg2send) {
		return err
	}

	return nil
}

func IsStun(packetBytes []byte) (*packet, error) {

	

	if len(packetBytes) == 0 {
		return nil, fmt.Errorf("error decode buffer")
	}

	if len(packetBytes) < 20 {
		return nil, errors.New("received data length too short")
	}

	if binary.BigEndian.Uint32(packetBytes[4:8]) != MagicCookie {
		return nil, errors.New("received data format mismatch")
	}

	if len(packetBytes) > math.MaxUint16+20 {
		return nil, errors.New("received data length too long")
	}
	return getStunFromUdpPayload(packetBytes)

}

func getStunFromUdpPayload(packetBytes []byte) (*packet, error) {

	pkt := new(packet)
	pkt.types = binary.BigEndian.Uint16(packetBytes[0:2])
	pkt.length = binary.BigEndian.Uint16(packetBytes[2:4])
	pkt.transID = packetBytes[4:20]
	pkt.attributes = make([]attribute, 0, 10)
	packetBytes = packetBytes[20:]
	for pos := uint16(0); pos+4 < uint16(len(packetBytes)); {
		types := binary.BigEndian.Uint16(packetBytes[pos : pos+2])
		length := binary.BigEndian.Uint16(packetBytes[pos+2 : pos+4])
		end := pos + 4 + length
		if end < pos+4 || end > uint16(len(packetBytes)) {
			return nil, errors.New("received data format mismatch")
		}
		value := packetBytes[pos+4 : end]
		attribute := newAttribute(types, value)
		pkt.addAttribute(*attribute)
		pos += align(length) + 4
	}

	return pkt, nil

}


func (v *packet) bytes() []byte {
	packetBytes := make([]byte, 4)
	binary.BigEndian.PutUint16(packetBytes[0:2], v.types)
	binary.BigEndian.PutUint16(packetBytes[2:4], v.length)
	packetBytes = append(packetBytes, v.transID...)
	for _, a := range v.attributes {
		buf := make([]byte, 2)
		binary.BigEndian.PutUint16(buf, a.types)
		packetBytes = append(packetBytes, buf...)
		binary.BigEndian.PutUint16(buf, a.length)
		packetBytes = append(packetBytes, buf...)
		packetBytes = append(packetBytes, a.value...)
	}
	return packetBytes
}

func (opts FrameOptions) Payload2Pkg(payloadBytes []byte) ([]byte, error) {

	buf := gopacket.NewSerializeBuffer()

	serializeOpts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	var ip serializableNetworkLayer
	if opts.IP.isV4 {
		ip = &layers.IPv4{
			SrcIP:    opts.IP.Src.To4(),
			DstIP:    opts.IP.Dst.To4(),
			Protocol: layers.IPProtocolUDP,
			Version:  4,
			TTL:      64,
			// Id:       5432,
		}
	} else {
		ip = &layers.IPv6{
			SrcIP:      opts.IP.Src.To16(),
			DstIP:      opts.IP.Dst.To16(),
			NextHeader: layers.IPProtocolUDP,
			Version:    6,
			HopLimit:   64,
		}
		ip.LayerType()
	}

	udp := &layers.UDP{
		SrcPort: layers.UDPPort(opts.UDP.Src),
		DstPort: layers.UDPPort(opts.UDP.Dst),
		// we configured "Length" and "Checksum" to be set for us
	}
	udp.SetNetworkLayerForChecksum(ip)

	if opts.HWD.Dst != nil {

		ethernetType := layers.EthernetTypeIPv4
		if !opts.IP.isV4 {
			ethernetType = layers.EthernetTypeIPv6
		}

		eth := &layers.Ethernet{
			SrcMAC:       opts.HWD.Src,
			DstMAC:       opts.HWD.Dst,
			EthernetType: ethernetType,
		}

		err := gopacket.SerializeLayers(buf, serializeOpts, eth, ip, udp, gopacket.Payload(payloadBytes))
		if err != nil {
			return nil, err
		}

	} else {

		err := gopacket.SerializeLayers(buf, serializeOpts, ip, udp, gopacket.Payload(payloadBytes))
		if err != nil {
			return nil, err
		}
	}

	bufToSend := buf.Bytes()

	return bufToSend, nil

	// }
	// return false, nil, nil
}
