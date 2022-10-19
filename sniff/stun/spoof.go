//go:build linux

package stun

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type canSetNetLayer interface {
	SetNetworkLayerForChecksum(gopacket.NetworkLayer) error
}

func SpoofUDPIPv4(data []byte, spoof net.IP) ([]byte, error) {

	p := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)


	if p.Layer(layers.LayerTypeUDP) == nil {
		p = gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.NoCopy)
	}

	if p.Layer(layers.LayerTypeIPv4) == nil || p.Layer(layers.LayerTypeUDP) == nil {
		return nil,	fmt.Errorf("Unknown Packet.\n")
	}
	
	slayers := []gopacket.SerializableLayer{}
	for _, l := range p.Layers() {
		if l.LayerType() == layers.LayerTypeIPv4 {
			nnip := l.(gopacket.SerializableLayer).(*layers.IPv4)
			nnip.SrcIP = spoof
			slayers = append(slayers, nnip)
		} else {
			slayers = append(slayers, l.(gopacket.SerializableLayer))
			if h, ok := l.(canSetNetLayer); ok {
				if err := h.SetNetworkLayerForChecksum(p.NetworkLayer()); err != nil {
					return nil, err
				}
			}
		}
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err := gopacket.SerializeLayers(buf, opts, slayers...)
	if err != nil {
		return nil, fmt.Errorf("unable to reserialize layers with opts %#v: %v", opts, err)
	}

	return buf.Bytes(), nil
}

