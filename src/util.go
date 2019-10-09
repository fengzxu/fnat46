package main

import (
	"bytes"
	"fmt"
	"github.com/google/gopacket/layers"
	"github.com/intel-go/nff-go/packet"
	"github.com/intel-go/nff-go/types"
	"log"
	"net"
	"time"
	"unsafe"
)

type Nat46Config struct {
	v6port    uint16
	v6portMac types.MACAddress
	v6ip      types.IPv6Address
	v6prefix  types.IPv6Address
	v4port    uint16
	v4portMAC types.MACAddress
	v4ip      types.IPv4Address
}

type Nat64TableEntity struct {
	proto     uint8
	v6SrcIP   types.IPv6Address
	v6SrcPort uint16
	v6DstIP   types.IPv6Address
	v6DstPort uint16
	v6NodeMAC types.MACAddress
	v4SrcIP   types.IPv4Address
	v4SrcPort uint16
	v4DstIP   types.IPv4Address
	v4DstPort uint16
	v4NodeMAC types.MACAddress
	lastTime  time.Time
}

func (en Nat64TableEntity) String() string {
	return fmt.Sprintf("(%s)%s:%d->%s:%d \n (%s)%s:%d->%s:%d",
		en.v4NodeMAC.String(), en.v4SrcIP.String(), en.v4SrcPort,
		en.v4DstIP.String(), en.v4DstPort,
		en.v6NodeMAC.String(), en.v6SrcIP.String(), en.v6SrcPort,
		en.v6DstIP.String(), en.v6DstPort)
}

func (conf Nat46Config) Copy() interface{} {
	return Nat46Config{
		v6port:    0,
		v6portMac: types.MACAddress{},
		v6prefix:  types.IPv6Address{},
		v4port:    0,
		v4portMAC: types.MACAddress{},
	}
}

func (conf Nat46Config) Delete() {

}

func (conf Nat46Config) String() string {
	return fmt.Sprintf("nat46 config:\n"+
		"IPv6 port:\t%d\nIPv6 mac:\t%s\n"+
		"IPv4 port:\t%d\nIPv4 mac:\t%s\n"+
		"IPv6 prefix:\t%s\n",
		conf.v6port, conf.v6portMac, conf.v4port, conf.v4portMAC, conf.v6prefix)
}

func IP2IPv6addr(ip net.IP) types.IPv6Address {
	ipv6 := types.IPv6Address{}
	copy(ipv6[:], ip[:16])
	return ipv6
}

func IP2IPv4addr(ip net.IP) types.IPv4Address {
	ipv4bytes := ip.To4()
	return types.BytesToIPv4(ipv4bytes[0], ipv4bytes[1], ipv4bytes[2], ipv4bytes[3])
}

func SetIPv6UDPChecksum(pkt *packet.Packet, hWTXChecksum bool) {
	l3 := pkt.GetIPv6NoCheck()
	l4 := pkt.GetUDPNoCheck()
	if hWTXChecksum {
		l4.DgramCksum = packet.SwapBytesUint16(packet.CalculatePseudoHdrIPv6UDPCksum(l3, l4))
		l2len := uint32(types.EtherLen)
		if pkt.Ether.EtherType == types.SwapVLANNumber {
			l2len += types.VLANLen
		}
		pkt.SetTXIPv6UDPOLFlags(l2len, types.IPv6Len)
	} else {
		l4.DgramCksum = packet.SwapBytesUint16(packet.CalculateIPv6UDPChecksum(l3, l4,
			unsafe.Pointer(uintptr(unsafe.Pointer(l4))+uintptr(types.UDPLen))))
	}
}

func SetIPv6TCPChecksum(pkt *packet.Packet, hWTXChecksum bool) {
	l3 := pkt.GetIPv6NoCheck()
	l4 := pkt.GetTCPNoCheck()
	if hWTXChecksum {
		l4.Cksum = packet.SwapBytesUint16(packet.CalculatePseudoHdrIPv6TCPCksum(l3))
		l2len := uint32(types.EtherLen)
		if pkt.Ether.EtherType == types.SwapVLANNumber {
			l2len += types.VLANLen
		}
		pkt.SetTXIPv6TCPOLFlags(l2len, types.IPv6Len)
	} else {
		l4.Cksum = packet.SwapBytesUint16(packet.CalculateIPv6TCPChecksum(l3, l4,
			unsafe.Pointer(uintptr(unsafe.Pointer(l4))+types.TCPMinLen)))
	}
}

func SetIPv6ICMPChecksum(pkt *packet.Packet) {
	l3 := pkt.GetIPv6NoCheck()
	l4 := pkt.GetICMPNoCheck()
	l4.Cksum = packet.SwapBytesUint16(packet.CalculateIPv6ICMPChecksum(l3, l4,
		unsafe.Pointer(uintptr(unsafe.Pointer(l4))+types.ICMPLen)))
}

func SetIPv4UDPChecksum(pkt *packet.Packet, hWTXChecksum bool) {
	l3 := pkt.GetIPv4NoCheck()
	l4 := pkt.GetUDPNoCheck()
	if hWTXChecksum {
		l3.HdrChecksum = 0
		l4.DgramCksum = packet.SwapBytesUint16(packet.CalculatePseudoHdrIPv4UDPCksum(l3, l4))
		l2len := uint32(types.EtherLen)
		if pkt.Ether.EtherType == types.SwapVLANNumber {
			l2len += types.VLANLen
		}
		pkt.SetTXIPv4UDPOLFlags(l2len, types.IPv4MinLen)
	} else {
		l3.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(l3))
		l4.DgramCksum = packet.SwapBytesUint16(packet.CalculateIPv4UDPChecksum(l3, l4,
			unsafe.Pointer(uintptr(unsafe.Pointer(l4))+uintptr(types.UDPLen))))
	}
}

func SetIPv4TCPChecksum(pkt *packet.Packet, hWTXChecksum bool) {
	l3 := pkt.GetIPv4NoCheck()
	l4 := pkt.GetTCPNoCheck()
	if hWTXChecksum {
		l3.HdrChecksum = 0
		l4.Cksum = packet.SwapBytesUint16(packet.CalculatePseudoHdrIPv4TCPCksum(l3))
		l2len := uint32(types.EtherLen)
		if pkt.Ether.EtherType == types.SwapVLANNumber {
			l2len += types.VLANLen
		}
		pkt.SetTXIPv4TCPOLFlags(l2len, types.IPv4MinLen)
	} else {
		l3.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(l3))
		l4.Cksum = packet.SwapBytesUint16(packet.CalculateIPv4TCPChecksum(l3, l4,
			unsafe.Pointer(uintptr(unsafe.Pointer(l4))+types.TCPMinLen)))
	}
}

func SetIPv4ICMPChecksum(pkt *packet.Packet, hWTXChecksum bool) {
	l3 := pkt.GetIPv4NoCheck()
	if hWTXChecksum {
		l3.HdrChecksum = 0
		l2len := uint32(types.EtherLen)
		if pkt.Ether.EtherType == types.SwapVLANNumber {
			l2len += types.VLANLen
		}
		pkt.SetTXIPv4OLFlags(l2len, types.IPv4MinLen)
	} else {
		l3.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(l3))
	}
	l4 := pkt.GetICMPNoCheck()
	l4.Cksum = packet.SwapBytesUint16(packet.CalculateIPv4ICMPChecksum(l3, l4,
		unsafe.Pointer(uintptr(unsafe.Pointer(l4))+types.ICMPLen)))
}

func CalculatePktHash(proto int, srcIP string, srcPort uint16) string {
	//todo: implement a real one!
	return fmt.Sprintf("%d-%s-%d", proto, srcIP, srcPort)
}

func TranslateIcmp6To4(pkt *packet.Packet) *packet.Packet {

	pkt.ParseL3()
	ipv6 := pkt.GetIPv6NoCheck()
	if ipv6 == nil {
		return nil
	}
	icmp6 := pkt.GetICMPForIPv6()
	//drop "fe80:"pkg
	if bytes.Compare(ipv6.SrcAddr[:2], []byte{0xfe, 0x80}) == 0 {
		log.Println("it's a fe80 pkt,drop it.")
		return nil
	}
	naten := getNatDst6To4(pkt)
	if naten == nil {
		log.Println("<TranslateIcmp6To4> got icmpentity nil.")
		return nil
	}
	//log.Println("<TranslateIcmp6To4>,pkt:", ipv6.SrcAddr, ipv6.DstAddr)
	//log.Println("<TranslateIcmp6To4> en:", naten)
	pllen := int(packet.SwapBytesUint16(ipv6.PayloadLen)) - types.ICMPLen
	newPkt, err := packet.NewPacket()
	if err != nil {
		log.Println("new pkt error:", err.Error())
		return nil
	}

	packet.InitEmptyIPv4ICMPPacket(newPkt, uint(pllen))
	newPkt.ParseData()
	//L2
	l2 := newPkt.Ether
	l2.SAddr = naten.v6NodeMAC
	l2.DAddr = naten.v4NodeMAC
	l2.EtherType = types.SwapIPV4Number
	//L3
	l3 := newPkt.GetIPv4()
	l3.TimeToLive = ipv6.HopLimits
	l3.SrcAddr = naten.v4DstIP
	l3.DstAddr = naten.v4SrcIP
	l3.FragmentOffset = 0
	//L4
	l4 := newPkt.GetICMPNoCheck()
	switch icmp6.Type {
	case layers.ICMPv6TypeEchoRequest:
		l4.Type = layers.ICMPv4TypeEchoRequest
		l4.Code = icmp6.Code
	case layers.ICMPv6TypePacketTooBig:
		l4.Type = layers.ICMPv4TypeDestinationUnreachable
		l4.Code = layers.ICMPv4CodeHost
	case layers.ICMPv6TypeTimeExceeded:
		l4.Type = layers.ICMPv4TypeTimeExceeded
		l4.Code = layers.ICMPv4CodeTTLExceeded
	case layers.ICMPv6TypeParameterProblem:
		switch icmp6.Code {
		case layers.ICMPv6CodeErroneousHeaderField:
			l4.Type = layers.ICMPv4TypeParameterProblem
			l4.Code = layers.ICMPv4CodePointerIndicatesError
		case layers.ICMPv6CodeUnrecognizedNextHeader:
			l4.Type = layers.ICMPv4TypeDestinationUnreachable
			l4.Code = layers.ICMPv4CodeProtocol
		}
	}
	l4.Identifier = icmp6.Identifier
	l4.SeqNum = icmp6.SeqNum

	//Data
	//not zero-copy
	plBytes, ok := pkt.GetPacketPayload()
	if !ok {
		log.Println("get pkt payload bytes faild.")
		return nil
	}
	newPkt.PacketBytesChange(types.EtherLen+types.IPv4MinLen+types.ICMPLen, plBytes)

	SetIPv4ICMPChecksum(newPkt, true)

	return newPkt
}

func TranslateTCP6To4(pkt *packet.Packet) *packet.Packet {
	pkt.ParseL3()
	ipv6 := pkt.GetIPv6NoCheck()
	if ipv6 == nil {
		return nil
	}

	naten := getNatDst6To4(pkt)
	if naten == nil {
		log.Println("<TranslateTCP6To4> got icmpentity nil.")
		return nil
	}
	//log.Println("<TranslateTCP6To4> found en:\n", naten)
	pllen := int(packet.SwapBytesUint16(ipv6.PayloadLen)) - types.TCPMinLen
	newPkt, err := packet.NewPacket()
	if err != nil {
		log.Println("new pkt error:", err.Error())
		return nil
	}

	packet.InitEmptyIPv4TCPPacket(newPkt, uint(pllen))
	newPkt.ParseData()
	//L2
	l2 := newPkt.Ether
	l2.SAddr = naten.v6NodeMAC
	l2.DAddr = naten.v4NodeMAC
	l2.EtherType = types.SwapIPV4Number
	//L3
	l3 := newPkt.GetIPv4()
	//l3.TypeOfService
	l3.TimeToLive = ipv6.HopLimits
	l3.SrcAddr = naten.v4DstIP
	l3.DstAddr = naten.v4SrcIP
	l3.FragmentOffset = 0

	//set df flag
	//newPkt.PacketBytesChange(types.EtherLen+6, []byte{64, 00})

	//L4
	tcp6 := pkt.GetTCPForIPv6()
	l4 := newPkt.GetTCPForIPv4()
	l4.SrcPort = naten.v4DstPort
	l4.DstPort = naten.v4SrcPort
	l4.SentSeq = tcp6.SentSeq
	l4.TCPFlags = tcp6.TCPFlags
	l4.RecvAck = tcp6.RecvAck
	l4.RxWin = tcp6.RxWin
	l4.TCPUrp = tcp6.TCPUrp

	//all bytes except min header
	allBytes := pkt.GetRawPacketBytes()
	newPkt.PacketBytesChange(types.EtherLen+types.IPv4MinLen,
		allBytes[types.EtherLen+types.IPv6Len:])

	SetIPv4TCPChecksum(newPkt, true)

	return newPkt
}

func TranslateUDP6To4(pkt *packet.Packet) *packet.Packet {
	pkt.ParseL3()
	ipv6 := pkt.GetIPv6NoCheck()
	if ipv6 == nil {
		log.Println("no ipv6 header on dealing TranslateUDP6To4!")
		return nil
	}
	naten := getNatDst6To4(pkt)
	log.Println("got en:", naten, "\n now return 6->4 pkt...")
	if naten == nil {
		log.Println("<TranslateUDP6To4> got icmpentity nil.")
		return nil
	}
	pllen := int(packet.SwapBytesUint16(ipv6.PayloadLen)) - types.UDPLen
	newPkt, err := packet.NewPacket()
	if err != nil {
		log.Println("new pkt error:", err.Error())
		return nil
	}

	packet.InitEmptyIPv4UDPPacket(newPkt, uint(pllen))
	newPkt.ParseData()
	//L2
	l2 := newPkt.Ether
	l2.SAddr = naten.v6NodeMAC
	l2.DAddr = naten.v4NodeMAC
	l2.EtherType = types.SwapIPV4Number
	//L3
	l3 := newPkt.GetIPv4()
	//l3.TypeOfService
	l3.TotalLength = packet.SwapBytesUint16(packet.SwapBytesUint16(ipv6.PayloadLen) + types.IPv4MinLen)
	l3.TimeToLive = ipv6.HopLimits
	l3.SrcAddr = naten.v4DstIP
	l3.DstAddr = naten.v4SrcIP
	l3.PacketID = 1234
	//set df flag
	//newPkt.PacketBytesChange(types.EtherLen+6, []byte{64, 00})

	//L4
	udp6 := pkt.GetUDPForIPv6()
	l4 := newPkt.GetUDPForIPv4()
	l4.SrcPort = packet.SwapBytesUint16(naten.v4DstPort)
	l4.DstPort = packet.SwapBytesUint16(naten.v4SrcPort)
	l4.DgramLen = udp6.DgramLen

	//DATA
	data, ok := pkt.GetPacketPayload()
	if !ok {
		log.Println("get udp data faild.")
	} else {
		newPkt.PacketBytesChange(types.EtherLen+types.IPv4MinLen+types.UDPLen, data)
	}

	SetIPv4UDPChecksum(newPkt, true)
	return newPkt
}

func TranslateIcmp4To6(pkt *packet.Packet) *packet.Packet {
	pkt.ParseL3()
	ipv4 := pkt.GetIPv4NoCheck()
	if ipv4 == nil {
		return nil
	}
	icmp4 := pkt.GetICMPForIPv4()
	naten := getNatDst4To6(pkt)
	if naten == nil {
		log.Println("get naten on TranslateIcmp4To6 is nil. return.")
		return nil
	}
	//log.Println("en:", naten)
	//log.Println("now generate a icmp4->6 pkt...")
	pllen := int(packet.SwapBytesUint16(ipv4.TotalLength)) - types.IPv4MinLen - types.ICMPLen
	newPkt, err := packet.NewPacket()
	if err != nil {
		log.Println("new pkt error:", err.Error())
		return nil
	}
	packet.InitEmptyIPv6ICMPPacket(newPkt, uint(pllen))
	newPkt.ParseData()
	//L2
	l2 := newPkt.Ether
	l2.SAddr = naten.v4NodeMAC
	l2.DAddr = naten.v6NodeMAC
	l2.EtherType = types.SwapIPV6Number
	//L3
	l3 := newPkt.GetIPv6NoCheck()
	l3.HopLimits = ipv4.TimeToLive
	l3.SrcAddr = naten.v6SrcIP
	l3.DstAddr = naten.v6DstIP
	//L4
	l4 := newPkt.GetICMPNoCheck()
	switch icmp4.Type {
	case layers.ICMPv4TypeEchoRequest:
		l4.Type = layers.ICMPv6TypeEchoRequest
		l4.Code = icmp4.Code
	case layers.ICMPv4TypeEchoReply:
		l4.Type = layers.ICMPv6TypeEchoReply
		l4.Code = icmp4.Code
	case layers.ICMPv4TypeInfoRequest, layers.ICMPv4TypeInfoReply,
		layers.ICMPv4TypeAddressMaskRequest, layers.ICMPv4TypeAddressMaskReply,
		layers.ICMPv4TypeRouterSolicitation, layers.ICMPv4TypeRouterAdvertisement:
		return nil
	case 3: //
		switch icmp4.Code {
		case 0, 1:
			l4.Type = 3
			l4.Code = 0
		case 2:
			l4.Type = 4
			l4.Code = 1
		case 3:
			l4.Type = 4
			l4.Code = 0
		case 4:
			l4.Type = 2
			l4.Code = 0
		case 5, 6, 7, 8:
			l4.Type = layers.ICMPv6TypeParameterProblem
			l4.Code = 0
		case 9, 10:
			l4.Type = layers.ICMPv6TypeDestinationUnreachable
			l4.Code = 1
		case 11, 12:
			l4.Type = layers.ICMPv6TypeDestinationUnreachable
			l4.Code = 0
		case 13:
			l4.Type = layers.ICMPv6TypeDestinationUnreachable
			l4.Code = 0
		case 14:
			return nil
		}
	}
	l4.Identifier = icmp4.Identifier
	l4.SeqNum = icmp4.SeqNum

	//Data
	//not zero-copy
	plBytes, ok := pkt.GetPacketPayload()
	if !ok {
		log.Println("get pkt payload bytes faild.")
		return nil
	}
	newPkt.PacketBytesChange(types.EtherLen+types.IPv6Len+types.ICMPLen, plBytes)

	SetIPv6ICMPChecksum(newPkt)

	return newPkt
}

func TranslateTCP4To6(pkt *packet.Packet) *packet.Packet {
	pkt.ParseL3()
	ipv4 := pkt.GetIPv4NoCheck()
	if ipv4 == nil {
		return nil
	}
	naten := getNatDst4To6(pkt)
	if naten == nil {
		log.Println("get naten on TranslateTCP4To6 is nil. return.")
		return nil
	}
	pllen := int(packet.SwapBytesUint16(ipv4.TotalLength)) - types.IPv4MinLen - types.TCPMinLen
	newPkt, err := packet.NewPacket()
	if err != nil {
		log.Println("new pkt error:", err.Error())
		return nil
	}

	packet.InitEmptyIPv6TCPPacket(newPkt, uint(pllen))
	newPkt.ParseData()
	//L2
	l2 := newPkt.Ether
	l2.SAddr = naten.v4NodeMAC
	l2.DAddr = naten.v6NodeMAC
	l2.EtherType = types.SwapIPV6Number
	//L3
	l3 := newPkt.GetIPv6NoCheck()
	l3.HopLimits = ipv4.TimeToLive
	l3.SrcAddr = naten.v6SrcIP
	l3.DstAddr = naten.v6DstIP

	//all bytes except min header
	allBytes := pkt.GetRawPacketBytes()
	newPkt.PacketBytesChange(types.EtherLen+types.IPv6Len,
		allBytes[types.EtherLen+types.IPv4MinLen:])

	//L4
	tcp4 := pkt.GetTCPForIPv4()
	l4 := newPkt.GetTCPForIPv6()
	l4.SrcPort = packet.SwapBytesUint16(naten.v6SrcPort)
	l4.DstPort = packet.SwapBytesUint16(naten.v6DstPort)
	l4.SentSeq = tcp4.SentSeq
	l4.TCPFlags = tcp4.TCPFlags
	l4.RecvAck = tcp4.RecvAck
	l4.RxWin = tcp4.RxWin
	l4.TCPUrp = tcp4.TCPUrp

	SetIPv6TCPChecksum(newPkt, true)

	return newPkt
}

func TranslateUDP4To6(pkt *packet.Packet) *packet.Packet {
	pkt.ParseL3()
	ipv4 := pkt.GetIPv4NoCheck()
	if ipv4 == nil {
		return nil
	}
	naten := getNatDst4To6(pkt)
	//log.Println("ok,get naten:\n", naten, "\nnow genarate TranslateUDP4To6 pkg ...")
	if naten == nil {
		log.Println("get naten on TranslateUDP4To6 is nil. return.")
		return nil
	}
	pllen := int(packet.SwapBytesUint16(ipv4.TotalLength)) - types.UDPLen
	newPkt, err := packet.NewPacket()
	if err != nil {
		log.Println("new pkt error:", err.Error())
		return nil
	}

	packet.InitEmptyIPv6UDPPacket(newPkt, uint(pllen))
	newPkt.ParseData()
	//L2
	l2 := newPkt.Ether
	l2.SAddr = naten.v4NodeMAC
	l2.DAddr = naten.v6NodeMAC
	l2.EtherType = types.SwapIPV6Number
	//L3
	l3 := newPkt.GetIPv6NoCheck()
	l3.HopLimits = ipv4.TimeToLive
	l3.SrcAddr = naten.v6SrcIP
	l3.DstAddr = naten.v6DstIP
	//L4
	udp4 := pkt.GetUDPForIPv4()
	l4 := newPkt.GetUDPForIPv6()
	l4.SrcPort = packet.SwapBytesUint16(naten.v6SrcPort)
	l4.DstPort = packet.SwapBytesUint16(naten.v6DstPort)
	l4.DgramLen = udp4.DgramLen

	//DATA
	data, ok := pkt.GetPacketPayload()
	if !ok {
		log.Println("get udp data faild.")
	} else {
		newPkt.PacketBytesChange(types.EtherLen+types.IPv6Len+types.UDPLen, data)
	}

	SetIPv6UDPChecksum(newPkt, true)

	return newPkt
}

func isFE80Pkt(pkt *packet.Packet) bool {
	if bytes.Compare(pkt.GetIPv6NoCheck().SrcAddr[:2], []byte{0xfe, 0x80}) == 0 {
		return true
	}
	return false
}
