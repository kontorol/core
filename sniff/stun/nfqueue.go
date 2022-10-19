//go:build linux

package stun

import (
	"context"
	"fmt"
	"time"

	"github.com/florianl/go-nfqueue"
)

// outgoingPacket, err := ProcessIP(*a.Payload, q.spoofIP)
// if err != nil || outgoingPacket == nil {
// 	fmt.Printf("%s", err)
// 	nf.SetVerdict(id, nfqueue.NfDrop)
// }

type NFQUEUE struct {
	conf   nfqueue.Config
}

func NewNFQ(nf uint16) NFQUEUE {

	n := NFQUEUE{
		conf: nfqueue.Config{
			NfQueue:      nf,
			MaxPacketLen: 0xFFFF,
			MaxQueueLen:  0xFF,
			Copymode:     nfqueue.NfQnlCopyPacket,
			WriteTimeout: 15 * time.Millisecond,
		},
	}
	return n
}

func (s Spoof) StartNFQ() {

	nf, err := nfqueue.Open(&s.queue.conf)
	if err != nil {
		fmt.Println("could not open nfqueue socket:", err)
		return
	}
	defer nf.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()


	fn := func(a nfqueue.Attribute) int {

		id := *a.PacketID

		outgoingPacket, err := SpoofUDPIPv4(*a.Payload, s.md.spoofIP)
		if err != nil || outgoingPacket == nil {
			fmt.Printf("%s", err)
			nf.SetVerdict(id, nfqueue.NfDrop)
		} else {
			nf.SetVerdictModPacket(id, nfqueue.NfAccept, outgoingPacket)
		}

		return 0
	}

	var errfn nfqueue.ErrorFunc
	// Register your function to listen on nflqueue queue 100
	err = nf.RegisterWithErrorFunc(ctx, fn, errfn)
	if err != nil {
		fmt.Println(err)
		return
	}
	if errfn != nil {
		fmt.Println(errfn)
		return
	}

	// Block till the context expires
	<-ctx.Done()
}
