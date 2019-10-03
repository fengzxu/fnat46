package main

import (
	"bytes"
	"fmt"
	"github.com/intel-go/nff-go/packet"
	"github.com/intel-go/nff-go/types"
	"log"
	"net"
	"sync"
	"time"
)

var nat64Table, nat46Table, usedIPv4Port, ipNat46 sync.Map
var ipv4Pool []types.IPv4Address

func initNat64Table() {
	nat64Table = sync.Map{}
	nat46Table = sync.Map{}
}

/**
On NAT46 ,when IPv4 request a domain witch only have AAAA record from a DNS,
the DNS (called DNS46 for now) return a fake IPv4 routed to translator.
The fake IPv4 route rule must be add to IPv4 client router point to translater IPv4 .
Rules can be stateless (according to address prefix) or
stateful (ip pool that can be reused )

For now ,for a simply example, use stateless 10.255.255.0/24.
If use stateful ,add a timer action to remove expire 4-6.
(route add 10.0.0.0/24 via translater IPv4)

*/
func initNat46() {
	ipNat46 = sync.Map{}
}

func answerICMP6EchoReq4Me(pkt *packet.Packet) {
	answerPkg, err := packet.NewPacket()
	if err != nil {
		log.Println("generate new pkg error:", err.Error())
		return
	}
	//// TODO need to initilize new packet instead of copying
	packet.GeneratePacketFromByte(answerPkg, pkt.GetRawPacketBytes())
	answerPkg.ParseData()
	answerPkg.Ether.DAddr = pkt.Ether.SAddr
	answerPkg.Ether.SAddr = pkt.Ether.DAddr
	ipv6hdr := answerPkg.GetIPv6NoCheck()
	ipv6hdr.DstAddr = pkt.GetIPv6NoCheck().SrcAddr
	ipv6hdr.SrcAddr = pkt.GetIPv6NoCheck().DstAddr
	ipv6hdr.HopLimits = 64
	icmp6hdr := answerPkg.GetICMPForIPv6()
	icmp6hdr.Type = types.ICMPv6TypeEchoResponse
	SetIPv6ICMPChecksum(answerPkg)
	answerPkg.SendPacket(config.v6port)
}

func answerNS4Me(pkt *packet.Packet) {
	answerPkg, err := packet.NewPacket()
	if err != nil {
		log.Println("generate new pkg error:", err.Error())
		return
	}
	packet.InitICMPv6NeighborAdvertisementPacket(answerPkg,
		config.v6portMac, pkt.Ether.SAddr,
		config.v6ip, pkt.GetIPv6NoCheck().SrcAddr)
	SetIPv6ICMPChecksum(answerPkg)
	answerPkg.SendPacket(config.v6port)
}

func setupNewIcmp6EN(pkt *packet.Packet) *Nat64TableEntity {
	ipv6hrd := pkt.GetIPv6NoCheck()
	if ipv6hrd == nil {
		return nil
	}
	v6dstIP := ipv6hrd.DstAddr
	if pkt.GetICMPForIPv6() != nil && pkt.GetICMPForIPv6().Type == types.ICMPv6NeighborSolicitation {
		v6dstIP = pkt.GetICMPv6NeighborSolicitationMessage().TargetAddr
	}
	newIcmp6EN := &Nat64TableEntity{
		proto:     ipv6hrd.Proto,
		v6SrcIP:   ipv6hrd.SrcAddr,
		v6SrcPort: 0,
		v6DstIP:   v6dstIP,
		v6NodeMAC: pkt.Ether.SAddr,
		v6DstPort: 0,
		v4SrcIP:   getAviableIPv4IcmpDst(),
		v4SrcPort: 0,
		v4NodeMAC: types.MACAddress{0, 0, 0, 0, 0, 0},
		v4DstIP:   getNatIPv4FromIPv6(v6dstIP),
		v4DstPort: 0,
		lastTime:  time.Now(),
	}
	log.Println("new icmp6 nat64entity.")
	//on v4nat64table ,treat arp/icmp type as types.ICMPv6Number. type TCP/UDP are the same code.
	v4hash := CalculatePktHash(int(types.ICMPv6Number), newIcmp6EN.v4DstIP.String(), 0)
	log.Println("save v4hash:", v4hash)
	nat46Table.Store(v4hash, newIcmp6EN)
	log.Println("stored v4 mac:", newIcmp6EN.v4NodeMAC)
	//is FE80 ? dont't save to nat64
	if isFE80Pkt(pkt) {
		newIcmp6EN.v6SrcIP = getNatIPv6FromIPv4(newIcmp6EN.v4DstIP)
	}
	v6hash := CalculatePktHash(int(types.ICMPv6Number), newIcmp6EN.v6SrcIP.String(), 0)
	nat64Table.Store(v6hash, newIcmp6EN)
	log.Println("save v6hash:", v6hash)
	return newIcmp6EN
}

/**
Send a new arp request to the ipv4 target to create the init NS/NA nat64 entify
on first connect to ipv4 target without a NS/NA nat64 entify.
to do that,store a new arpentity , send a arp request to the ipv4 target
and waite for reply to update target mac.
*/
func setupNewArpRequestForIPv4Target(srcMac types.MACAddress, srcIP, dstIP types.IPv4Address) bool {
	arpPkg, err := packet.NewPacket()
	if err != nil {
		log.Println("generate new pkg error:", err.Error())
		return false
	}
	packet.InitARPRequestPacket(arpPkg, srcMac, srcIP, dstIP)
	return arpPkg.SendPacket(config.v4port)
}

func dealPktIPv6NSonV6port(pkt *packet.Packet) {
	log.Println("got a NS pkt for target")
	pktAnswer, err := packet.NewPacket()
	if err != nil {
		log.Println("generate new pkg error:", err.Error())
		return
	}
	pkt.ParseL4ForIPv6()
	taraddr := pkt.GetICMPv6NeighborSolicitationMessage().TargetAddr
	ipv4addr := getNatIPv4FromIPv6(taraddr)
	if isNat46TarIPv4(ipv4addr) {
		//sec 1: nat46
		log.Println("it's a nat46 NS.")
		packet.InitICMPv6NeighborAdvertisementPacket(pktAnswer, pkt.Ether.DAddr, config.v6portMac,
			taraddr, pkt.GetIPv6NoCheck().SrcAddr)
		SetIPv6ICMPChecksum(pktAnswer)
		pktAnswer.SendPacket(config.v6port)
		log.Println("ok, retuen a NA pkt for v6 tar.")
	} else {
		//sec 2: nat64
		log.Println("it's a nat64 NS.")
		natEN := getNatDst6To4(pkt)
		packet.InitARPRequestPacket(pktAnswer, config.v4portMAC, natEN.v4SrcIP, natEN.v4DstIP)
		pktAnswer.SendPacket(config.v4port)
		log.Println("ok, send a NA pkt to v4 tar.")
	}
}

func dealPktIPv6ToIPv4ICMP(pkt *packet.Packet) {
	log.Println("got a ICMP6 pkt,processing...")
	newPkt := TranslateIcmp6To4(pkt)
	if newPkt != nil {
		newPkt.SendPacket(config.v4port)
	}
}

func dealPktIPv6ToIPv4UDP(pkt *packet.Packet) {
	log.Println("got a UDP6 pkt from",
		pkt.GetIPv6NoCheck().SrcAddr, "->", pkt.GetIPv6NoCheck().DstAddr)
	newPkt := TranslateUDP6To4(pkt)
	if newPkt != nil {
		newPkt.SendPacket(config.v4port)
	} else {
		log.Println("new udpv4 pkg nil...")
	}
}

func dealPktIPv6ToIPv4TCP(pkt *packet.Packet) {
	log.Println("got a TCP6 pkt from",
		pkt.GetIPv6NoCheck().SrcAddr, "->", pkt.GetIPv6NoCheck().DstAddr)
	newPkt := TranslateTCP6To4(pkt)
	if newPkt != nil {
		newPkt.SendPacket(config.v4port)
	} else {
		log.Println("<dealPktIPv6ToIPv4TCP> got pkg nil...")
	}
}

func answerPktIPv4ArpRequestForMe(pkt *packet.Packet) {
	arp := pkt.GetARPCheckVLAN()
	answerPacket, err := packet.NewPacket()
	if err != nil {
		log.Println("error on generate new pkt:", err.Error())
		return
	}
	packet.InitARPReplyPacket(answerPacket, config.v4portMAC, arp.SHA, types.ArrayToIPv4(arp.TPA), types.ArrayToIPv4(arp.SPA))
	answerPacket.SendPacket(config.v4port)
}

/**
 */
func dealPktNat46ArpRequest(pkt *packet.Packet) {
	arp := pkt.GetARPCheckVLAN()
	if arp == nil {
		return
	}
	log.Println("dealPktNat46ArpRequest:", arp.SHA, arp.THA, arp.SPA, arp.TPA)
	nat46EN := getNatDst4To6(pkt)
	if nat46EN == nil {
		log.Println("get nat46EN on dealPktNat46ArpRequest nil!")
		return
	}
	newNSpkt, err := packet.NewPacket()
	if err != nil {
		log.Println("generate new pkg error:", err.Error())
		return
	}
	packet.InitICMPv6NeighborSolicitationPacket(newNSpkt, nat46EN.v4NodeMAC,
		nat46EN.v6SrcIP, nat46EN.v6DstIP)
	SetIPv6ICMPChecksum(newNSpkt)
	newNSpkt.SendPacket(config.v6port)
}

/**
Got a NA pkt on v6port,it's a response for the NS pkt sent by translator.
Now,need to translate NS pkt to a ipv4 arp response pkt.
*/
func dealPktNat46ArpResponse(pkt *packet.Packet) {
	log.Println("ok,got a NA pkt for the arp request send before.")
	ipv6hdr := pkt.GetIPv6NoCheck()
	if ipv6hdr == nil {
		return
	}
	v6hash := CalculatePktHash(types.ICMPv6Number, ipv6hdr.SrcAddr.String(), 0)
	natENObj, ok := nat46Table.Load(v6hash)
	if !ok {
		log.Println("load natEN on dealPktNat46ArpResponse nil!")
		return
	}
	natEN := natENObj.(*Nat64TableEntity)
	log.Println("found naten46 en and update v6mac:", natEN)
	natEN.v6NodeMAC = pkt.Ether.SAddr
	//newArpPkt, err := packet.NewPacket()
	//if err != nil {
	//	log.Println("generate new pkg error:", err.Error())
	//	return
	//}
	//packet.InitARPReplyPacket(newArpPkt, natEN.v6NodeMAC, natEN.v4NodeMAC, natEN.v4DstIP, natEN.v4SrcIP)
	//log.Println("now ,send the translated arp response pkt to v4 port:", natEN.v4DstIP, natEN.v4SrcIP)
	//newArpPkt.SendPacket(config.v4port)
}

/**
temp resolve the fake ipv4 to real ipv6 by replace the last 8 bits.
On product,it must from a DNS46 server to get the fake ipv4 to real ipv6.
*/
func tempNat46IPv4To6(ipv4 types.IPv4Address) (types.IPv6Address, bool) {
	ipv6 := IP2IPv6addr(net.ParseIP("6001:db8::").To16())
	ipv6[15] = types.IPv4ToBytes(ipv4)[3]
	ipNat46.Store(ipv4.String(), ipv6)
	ipNat46.Store(ipv6.String(), ipv4)
	return ipv6, true
}

func answerICMPEchoReqForMe(pkt *packet.Packet) {
	answerPacket, err := packet.NewPacket()
	if err != nil {
		log.Println("error on generate new pkt:", err.Error())
		return
	}
	// TODO need to initilize new packet instead of copying
	packet.GeneratePacketFromByte(answerPacket, pkt.GetRawPacketBytes())
	answerPacket.Ether.DAddr = pkt.Ether.SAddr
	answerPacket.Ether.SAddr = pkt.Ether.DAddr
	answerPacket.ParseL3()
	pktIPv4 := answerPacket.GetIPv4NoCheck()
	pktIPv4.DstAddr = pkt.GetIPv4NoCheck().SrcAddr
	pktIPv4.SrcAddr = pkt.GetIPv4NoCheck().DstAddr
	answerPacket.ParseL4ForIPv4()
	pktICMP := answerPacket.GetICMPNoCheck()
	pktICMP.Type = types.ICMPTypeEchoResponse
	pktIPv4.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(pktIPv4))
	answerPacket.ParseL7(types.ICMPNumber)
	pktICMP.Cksum = packet.SwapBytesUint16(packet.CalculateIPv4ICMPChecksum(pktIPv4, pktICMP, answerPacket.Data))
	answerPacket.SendPacket(config.v4port)
}

func dealPktIPv4ToIPv6EchoRequest(pkt *packet.Packet) {
	log.Println("got a ICMP4 echo request pkt on ipv4 port,now translate 4->6...")
	newPkt := TranslateIcmp4To6(pkt)
	if newPkt != nil {
		log.Println("TranslateIcmp4To6 :before(4):", pkt.GetIPv4NoCheck().SrcAddr, pkt.Ether.SAddr, pkt.GetIPv4NoCheck().DstAddr, pkt.Ether.DAddr)
		log.Println("TranslateIcmp4To6 after(6):", newPkt.GetIPv6NoCheck().SrcAddr, newPkt.Ether.SAddr, newPkt.GetIPv6NoCheck().DstAddr, newPkt.Ether.DAddr)
		log.Println("now ,send the icmp6 echo to v6port.")
		newPkt.SendPacket(config.v6port)
	}

}

func dealPktIPv4ToIPv6EchoResponse(pkt *packet.Packet) {
	log.Println("got a ICMP4 echo response pkt on ipv4 port")

	newPkt := TranslateIcmp4To6(pkt)
	if newPkt != nil {
		newPkt.SendPacket(config.v6port)
	}
}

func dealPktIPv4ToIPv6UDP(pkt *packet.Packet) {
	log.Println("got a UDP4 pkt from",
		pkt.GetIPv4NoCheck().SrcAddr, "->", pkt.GetIPv4NoCheck().DstAddr)
	newPkt := TranslateUDP4To6(pkt)
	if newPkt != nil {
		newPkt.SendPacket(config.v6port)
	}
}

func dealPktIPv4ToIPv6TCP(pkt *packet.Packet) {
	log.Println("got a TCP4 pkt from",
		pkt.GetIPv4NoCheck().SrcAddr, "->", pkt.GetIPv4NoCheck().DstAddr)
	newPkt := TranslateTCP4To6(pkt)
	if newPkt != nil {
		newPkt.SendPacket(config.v6port)
	}
}

func dealPktIPv4ArpReply(pkt *packet.Packet) {
	log.Println("got a arp reply.")
	//nat64 or nat46
	var natEN *Nat64TableEntity
	if isV4ipINV4Array(config.v4pool, pkt.GetIPv4NoCheck().DstAddr) {
		//nat64
		natEN = getNatDst6To4(pkt)
	} else {
		//nat46
		natEN = getNatDst4To6(pkt)
	}

	if natEN == nil {
		log.Println("<dealPktIPv4ArpReply> get natEN nil!")
		return
	}
	log.Println("now update v4 mac to:", pkt.Ether.SAddr)
	natEN.v4NodeMAC = pkt.Ether.SAddr
	//genarate a NA pkt to ipv6 client
	answerPacket, err := packet.NewPacket()
	if err != nil {
		log.Println("generate new pkg error:", err.Error())
		return
	}
	packet.InitICMPv6NeighborAdvertisementPacket(answerPacket, natEN.v4NodeMAC, natEN.v6NodeMAC,
		natEN.v6DstIP, natEN.v6SrcIP)
	SetIPv6ICMPChecksum(answerPacket)
	answerPacket.SendPacket(config.v6port)
	log.Println("sent a NA pkt.")
}

func getNatDst6To4(pkt *packet.Packet) *Nat64TableEntity {
	ipv6hrd := pkt.GetIPv6NoCheck()
	v6srcPort, v6dstPort, v4srcPort := uint16(0), uint16(0), uint16(0)
	var v6dstIP types.IPv6Address
	var v6hash string
	if pkt.GetICMPForIPv6() != nil && pkt.GetICMPForIPv6().Type == types.ICMPv6NeighborSolicitation {
		//got a new NS pkg,means new session .
		//now prepare new icmp6 entity
		return setupNewIcmp6EN(pkt)
	} else {
		switch ipv6hrd.Proto {
		case types.TCPNumber:
			v4srcPort = pkt.GetTCPForIPv6().SrcPort
			v6srcPort = v4srcPort
			v6dstIP = ipv6hrd.DstAddr
			v6dstPort = pkt.GetTCPForIPv6().DstPort
		case types.UDPNumber:
			v4srcPort = pkt.GetUDPForIPv6().SrcPort
			v6srcPort = v4srcPort
			v6dstIP = ipv6hrd.DstAddr
			v6dstPort = pkt.GetUDPForIPv6().DstPort
		case types.ICMPv6Number:
			v4srcPort = 0
			v6srcPort = v4srcPort
			v6dstIP = ipv6hrd.DstAddr
			v6dstPort = 0
		}
		//got icmpv6 v6hash entify created on NS/NA before
		v6hash = CalculatePktHash(int(types.ICMPv6Number), ipv6hrd.SrcAddr.String(), 0)
		//log.Println("search icmpv6 for v6hash:", v6hash)
		nat64Icmp6ENObj, ok := nat64Table.Load(v6hash)
		if ok {
			//update icmp6en used last time
			nat64Icmp6ENObj.(*Nat64TableEntity).lastTime = time.Now()
		} else {
			got := false
			//must been removed because of expired
			log.Println("no init icmpv6 entify found , now setup a arp pkg and wait for NS/NA.")
			newIcmpEn := setupNewIcmp6EN(pkt)
			log.Println("send new arp request pkt:",
				setupNewArpRequestForIPv4Target(newIcmpEn.v6NodeMAC, newIcmpEn.v4SrcIP, newIcmpEn.v4DstIP))
			zeroMac := types.MACAddress{0, 0, 0, 0, 0, 0}
			for i := 1; i < 10; i++ {
				time.Sleep(time.Duration(100) * time.Millisecond)
				obj, ok := nat64Table.Load(v6hash)
				if ok && obj.(*Nat64TableEntity).v4NodeMAC != zeroMac {
					//log.Println("ok,got in", i*100, "Millisecond.")
					got = true
					nat64Icmp6ENObj = obj
					break
				}
			}
			if !got {
				log.Println("waited for 1 second,no luck,abort.")
				return nil
			}
		}
		//now search nat64 using
		var newEN *Nat64TableEntity
		v6hash = CalculatePktHash(int(ipv6hrd.Proto), nat64Icmp6ENObj.(*Nat64TableEntity).v6SrcIP.String(), packet.SwapBytesUint16(v6srcPort))
		log.Println("search tcp/udp/icmp entity for v6hash:", v6hash)
		newENObj, found := nat64Table.Load(v6hash)
		if found {
			newEN = newENObj.(*Nat64TableEntity)
			newEN.lastTime = time.Now()
			return newEN
		}
		log.Println("not found. now create a new one.")
		//new tcp/udp/icmp entity
		v4srcIP, v4srcPort, got := getAviableIPv4DstStateFull(ipv6hrd)
		if !got {
			log.Println("error: ipv4 pool used out!!! ")
			return nil
		}
		newEN = &Nat64TableEntity{
			proto:     ipv6hrd.Proto,
			v6SrcIP:   ipv6hrd.SrcAddr,
			v6SrcPort: v6srcPort,
			v6DstIP:   v6dstIP,
			v6NodeMAC: pkt.Ether.SAddr,
			v6DstPort: v6dstPort,
			v4SrcIP:   v4srcIP,
			v4SrcPort: v4srcPort,
			v4NodeMAC: nat64Icmp6ENObj.(*Nat64TableEntity).v4NodeMAC,
			v4DstIP:   nat64Icmp6ENObj.(*Nat64TableEntity).v4DstIP,
			v4DstPort: v6dstPort,
			lastTime:  time.Now(),
		}
		//save
		log.Println("new tcp/udp/icmp v6 nat64entity.")
		log.Println("save v6hash:", v6hash)
		nat64Table.Store(v6hash, newEN)
		//on v4nat64table ,treat arp/icmp type as types.ICMPv6Number. type TCP/UDP are the same code.
		v4hash := CalculatePktHash(int(ipv6hrd.Proto), newEN.v4DstIP.String(), packet.SwapBytesUint16(newEN.v4DstPort))
		log.Println("and v4hash:", v4hash)
		nat46Table.Store(v4hash, newEN)
		//log.Println("stored v4 mac:", newEN.v4NodeMAC)
		return newEN
	}
}

func getNatDst4To6(pkt *packet.Packet) *Nat64TableEntity {
	var v4hash string
	var v6hash string
	var nat46EN interface{}
	var ok bool
	if pkt.Ether.EtherType == types.IPV6Number {
		ipv6 := pkt.GetIPv6NoCheck()
		switch ipv6.Proto {
		case types.TCPNumber:
			v4hash = CalculatePktHash(types.TCPNumber, ipv6.SrcAddr.String(), packet.SwapBytesUint16(pkt.GetTCPForIPv6().SrcPort))
		case types.UDPNumber:
			v4hash = CalculatePktHash(types.UDPNumber, ipv6.SrcAddr.String(), packet.SwapBytesUint16(pkt.GetUDPForIPv6().SrcPort))
		case types.ICMPv6Number:
			v4hash = CalculatePktHash(types.ICMPv6Number, ipv6.SrcAddr.String(), 0)
		}
		log.Println("<getNatDst4To6> search for v6hash:", v6hash)
		nat46EN, ok = nat46Table.Load(v4hash)
	} else {
		arp := pkt.GetARPNoCheck()
		if packet.SwapBytesUint16(arp.Operation) == packet.ARPRequest {
			//new nat46 arp session,setup a new Nat64TableEntity.
			return setupNewIcmpV4EN(*pkt)
		} else if packet.SwapBytesUint16(arp.Operation) == packet.ARPReply {
			v4hash = CalculatePktHash(types.ICMPv6Number, types.ArrayToIPv4(arp.SPA).String(), 0)
		} else {
			//arp/icmp type in hash is ICMPv6Number.
			ipv4 := pkt.GetIPv4NoCheck()
			switch ipv4.NextProtoID {
			case types.TCPNumber:
				v4hash = CalculatePktHash(types.TCPNumber, ipv4.SrcAddr.String(), packet.SwapBytesUint16(pkt.GetTCPForIPv4().SrcPort))
			case types.UDPNumber:
				v4hash = CalculatePktHash(types.UDPNumber, ipv4.SrcAddr.String(), packet.SwapBytesUint16(pkt.GetUDPForIPv4().SrcPort))
			case types.ICMPNumber:
				v4hash = CalculatePktHash(types.ICMPv6Number, ipv4.SrcAddr.String(), 0)
			}
		}
		log.Println("<getNatDst4To6> search for v4hash:", v4hash)
		nat46EN, ok = nat46Table.Load(v4hash)
	}
	if ok {
		log.Println("found:", nat46EN)
		nat46EN.(*Nat64TableEntity).lastTime = time.Now()
		return nat46EN.(*Nat64TableEntity)
	} else {
		//must been removed because of expired or never do arp.
		log.Println("no init icmpv4 entity found , now setup a NS pkt to v6 port and wait for arp response.")
		newIcmpEn := setupNewIcmpV4EN(*pkt)
		if newIcmpEn == nil {
			log.Println("setupNewIcmpV4EN faild.")
			return nil
		}
		log.Println("<getNatDst4To6>get newIcmpEn:", newIcmpEn)
		//log.Println("<getNatDst4To6>store v4hash:", v4hash)
		//nat46Table.Store(v4hash, newIcmpEn)
		//v6hash := CalculatePktHash(types.ICMPv6Number, newIcmpEn.v6DstIP.String(), 0)
		//log.Println("<getNatDst4To6>store v6hash:", v6hash)
		//nat46Table.Store(v6hash, newIcmpEn)
		log.Println("send new NS request pkt:", sendNewNSForIPv6Target(newIcmpEn))
		//wait for NA pkt.
		zeroMac := types.MACAddress{0, 0, 0, 0, 0, 0}
		for i := 1; i < 10; i++ {
			time.Sleep(time.Duration(100) * time.Millisecond)
			obj, ok := nat46Table.Load(v4hash)
			if ok && obj.(*Nat64TableEntity).v6NodeMAC != zeroMac {
				log.Println("ok,got in", i*100, "Millisecond:", obj.(*Nat64TableEntity))
				return obj.(*Nat64TableEntity)
			}
		}
		log.Println("waited for 1 second,no luck,abort.")
		//log.Println("getNatDst4To6 on no arp pkt:nil.")
		return nil
	}
}

func sendNewNSForIPv6Target(newIcmpEn *Nat64TableEntity) bool {
	newNSpkt, err := packet.NewPacket()
	if err != nil {
		log.Println("generate new pkg error:", err.Error())
		return false
	}
	packet.InitICMPv6NeighborSolicitationPacket(newNSpkt, newIcmpEn.v4NodeMAC,
		newIcmpEn.v6SrcIP, newIcmpEn.v6DstIP)
	SetIPv6ICMPChecksum(newNSpkt)
	return newNSpkt.SendPacket(config.v6port)
}

func setupNewIcmpV4EN(pkt packet.Packet) *Nat64TableEntity {
	var v4SrcIP, v4DstIP types.IPv4Address
	var ipv6Src, ipv6Dst types.IPv6Address
	//arp := pkt.GetARPNoCheck()
	//if arp !=nil &&packet.SwapBytesUint16(arp.Operation) == packet.ARPRequest {
	//	v4SrcIP = types.ArrayToIPv4(arp.SPA)
	//	v4DstIP = types.ArrayToIPv4(arp.TPA)
	//	ipv6Src = getNatIPv6FromIPv4(v4SrcIP)
	//	ipv6Dst, ok := tempNat46IPv4To6(v4DstIP)
	//}
	ipv4hdr := pkt.GetIPv4NoCheck()
	if ipv4hdr == nil {
		log.Println("setupNewIcmpV4EN: pkt ipv4hdr nil?????")
		return nil
	}
	v4SrcIP = ipv4hdr.SrcAddr
	v4DstIP = ipv4hdr.DstAddr
	ipv6Src = getNatIPv6FromIPv4(v4SrcIP)
	ipv6Dst, ok := tempNat46IPv4To6(v4DstIP)
	if !ok {
		log.Println("get Real ipv6 faild....")
		return nil
	}
	newEN := &Nat64TableEntity{
		proto:     types.ICMPv6Number,
		v6SrcIP:   ipv6Src,
		v6SrcPort: 0,
		v6DstIP:   ipv6Dst,
		v6DstPort: 0,
		//v6NodeMAC:
		v4SrcIP:   v4SrcIP,
		v4SrcPort: 0,
		v4DstIP:   v4DstIP,
		v4DstPort: 0,
		v4NodeMAC: pkt.Ether.SAddr,
	}
	log.Println("setupNewIcmpV4EN:", newEN)
	//save nat64 entity to both nat64table and nat46table
	v4hash := CalculatePktHash(types.ICMPv6Number, v4SrcIP.String(), 0)
	log.Println("v4hash:", v4hash)
	nat46Table.Store(v4hash, newEN)
	v6hash := CalculatePktHash(types.ICMPv6Number, ipv6Dst.String(), 0)
	log.Println("v6hash:", v6hash)
	nat46Table.Store(v6hash, newEN)
	return newEN
}

/**
get aviable IPv4 and port (IPv4+PORT）on ip protocal for nat64 && nat46
Can be stateless (statuc rules from file) or stateful (ipv4 pool)
*/
func getAviableIPv4DstStateFull(ipv6hdr *packet.IPv6Hdr) (types.IPv4Address, uint16, bool) {
	for _, ipv4 := range config.v4pool {
		for i := uint16(10000); i < 65000; i++ { //aviable port from 10000-65000
			usedKey := fmt.Sprintf("%s-%d-%d", ipv4.String(), ipv6hdr.Proto, i)
			//log.Println("<avia>search for", usedKey)
			_, got := usedIPv4Port.Load(usedKey)
			if !got { //yes,aviable
				usedIPv4Port.Store(usedKey, time.Now())
				return ipv4, packet.SwapBytesUint16(i), true
			}
		}
	}
	return 0, 0, false
}

/**
On NAT46,IPv4 port only deal with the special fake IPv4 .
For now ,for a simply example, use 10.255.255.0/24 to compare.
*/
func isNat46TarIPv4(ipv4 types.IPv4Address) bool {
	ipbytes := types.IPv4ToBytes(ipv4)
	if bytes.Compare(ipbytes[:3], net.ParseIP("10.255.255.0").To4()[:3]) == 0 {
		return true
	}
	return false
}

/**
get aviable IPv4 for all ICMP session(arp/icmp)
For now just return the first pool ipv4
*/
func getAviableIPv4IcmpDst() types.IPv4Address {
	return config.v4pool[0]
}

/**
remove expired Natdst6To4 and Natdst4To6 entity
*/
func RemoveExpiredNatEntity() {
	t := time.NewTicker(time.Duration(60 * time.Second))
	defer t.Stop()
	for {
		<-t.C
		nat64Table.Range(doRemoveNatDst64)
		nat46Table.Range(doRemoveNatDst46)
	}
}

func doRemoveNatDst64(k interface{}, v interface{}) bool {
	//expired in 60 seconds
	if v.(*Nat64TableEntity).lastTime.Add(60 * time.Second).Before(time.Now()) {
		log.Println("remove en with last time:", v.(*Nat64TableEntity).lastTime,
			"on", time.Now())
		nat64Table.Delete(k)
	}
	return true
}

func doRemoveNatDst46(k interface{}, v interface{}) bool {
	//expired in 60 seconds
	if v.(*Nat64TableEntity).lastTime.Add(60 * time.Second).Before(time.Now()) {
		log.Println("remove en with last time:", v.(*Nat64TableEntity).lastTime,
			"on", time.Now())
		nat46Table.Delete(k)
	}
	return true
}

/**
remove ExpiredIPv4Dst every 60 sec(s) second(s).
*/
func RemoveExpiredIPv4Dst() {
	t := time.NewTicker(time.Duration(60 * time.Second))
	defer t.Stop()
	for {
		<-t.C
		usedIPv4Port.Range(doRemoveIPv4Dst)
	}
}

/**
remove ExpiredIPv4Dst 60 seconds older than now.
*/
func doRemoveIPv4Dst(k, v interface{}) bool {
	if v.(time.Time).Add(60 * time.Second).Before(time.Now()) {
		log.Println("remove ipv4dst with last time:", v.(time.Time),
			"on", time.Now())
		usedIPv4Port.Delete(k)
	}
	return true
}

//func getAviableIPv4DstStateLess(ipv6hdr *packet.IPv6Hdr) (ipv4 types.IPv4Address, port uint16, ok bool) {
//	ok = false
//	return
//}

func getNatIPv4FromIPv6(ipv6 types.IPv6Address) types.IPv4Address {
	log.Println("getNatIPv4FromIPv6:", ipv6.String())
	//for now, 6-4 rule is just take the last 4*8 bit
	ipv4Bytes := [4]byte{}
	copy(ipv4Bytes[:], ipv6[12:])
	log.Println("getNatIPv4FromIPv6:", types.ArrayToIPv4(ipv4Bytes))
	return types.ArrayToIPv4(ipv4Bytes)
}

func getNatIPv6FromIPv4(ipv4 types.IPv4Address) types.IPv6Address {
	//for now, 6-4 rule is just ipv6 prefix plus ipv4
	ipv6Addr := config.v6prefix
	ipv4Bytes := types.IPv4ToBytes(ipv4)
	copy(ipv6Addr[12:], ipv4Bytes[:])
	return ipv6Addr
}

func isV4ipINV4Array(ips []types.IPv4Address, ip types.IPv4Address) bool {
	found := false
	for _, tip := range ips {
		if tip == ip {
			found = true
			break
		}
	}
	return found
}

/**
Get IPv6 target address from IP46Table.
Basic flow:
1、ipv4 client ask a domain ipv4 address from a DNS server;
2、DNS server recursive for forward the client request.If got AAAA only records,
then pick a available ipv4 from pool and setup a ip46 map entity;
3、reture the mapped ipv6;
*/
//func getIPv6FromIP46Table(ipv4 types.IPv4Address) types.IPv6Address {
//	ipv6, ok := nat46Table.Load(ipv4)
//	if ok {
//		return ipv6.(types.IPv6Address)
//	}
//	//new entity.  get from a pool
//	newIPv6 := getIPv6TargetFromIPv4v6(getAviableIPv4Map())
//	nat46Table.Store(ipv4, newIPv6)
//	return newIPv6
//}
