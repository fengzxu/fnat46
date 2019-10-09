package main

import (
	"bytes"
	"github.com/intel-go/nff-go/packet"
	"github.com/intel-go/nff-go/types"
	"log"
	"net"
	"sync"
	"time"
)

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

var nat64Table, nat46Table, usedIPv4Port, ipNat46 sync.Map
var ipv4Pool []types.IPv4Address

func initNat46Table() {
	nat64Table = sync.Map{}
	nat46Table = sync.Map{}
}

func initNat46Map() {
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
		v4SrcIP:   config.v4ip,
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
	//taraddr := pkt.GetICMPv6NeighborSolicitationMessage().TargetAddr
	packet.InitICMPv6NeighborAdvertisementPacket(pktAnswer, pkt.Ether.DAddr, pkt.Ether.SAddr,
		pkt.GetIPv6NoCheck().DstAddr, pkt.GetIPv6NoCheck().SrcAddr)
	SetIPv6ICMPChecksum(pktAnswer)
	pktAnswer.SendPacket(config.v6port)
	log.Println("ok, retuen a NA pkt .")
}

func dealPktIPv6ToIPv4ICMP(pkt *packet.Packet) {
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
	log.Println("send the pkt..")
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

	//nat46
	//natEN := getNatDst4To6(pkt)
	//
	//if natEN == nil {
	//	log.Println("<dealPktIPv4ArpReply> get natEN nil!")
	//	return
	//}
	//log.Println("now update v4 mac to:", pkt.Ether.SAddr)
	//natEN.v4NodeMAC = pkt.Ether.SAddr
	////genarate a NA pkt to ipv6 client
	//answerPacket, err := packet.NewPacket()
	//if err != nil {
	//	log.Println("generate new pkg error:", err.Error())
	//	return
	//}
	//packet.InitICMPv6NeighborAdvertisementPacket(answerPacket, natEN.v4NodeMAC, natEN.v6NodeMAC,
	//	natEN.v6DstIP, natEN.v6SrcIP)
	//SetIPv6ICMPChecksum(answerPacket)
	//answerPacket.SendPacket(config.v6port)
	//log.Println("sent a NA pkt.")
}

func getNatDst6To4(pkt *packet.Packet) *Nat64TableEntity {
	ipv6hrd := pkt.GetIPv6NoCheck()
	v6srcPort := uint16(0)
	var v6hash string

	switch ipv6hrd.Proto {
	case types.TCPNumber:
		//v4srcPort = pkt.GetTCPForIPv6().SrcPort
		v6srcPort = pkt.GetTCPForIPv6().SrcPort
		//v6dstIP = ipv6hrd.DstAddr
		//v6dstPort = pkt.GetTCPForIPv6().DstPort
	case types.UDPNumber:
		//v4srcPort = pkt.GetUDPForIPv6().SrcPort
		v6srcPort = pkt.GetUDPForIPv6().SrcPort
		//v6dstIP = ipv6hrd.DstAddr
		//v6dstPort = pkt.GetUDPForIPv6().DstPort
	case types.ICMPv6Number:
		//v4srcPort = 0
		v6srcPort = 0
		//v6dstIP = ipv6hrd.DstAddr
		//v6dstPort = 0
	}
	//now search nat46 using
	var newEN *Nat64TableEntity
	v6hash = CalculatePktHash(int(ipv6hrd.Proto), ipv6hrd.SrcAddr.String(), packet.SwapBytesUint16(v6srcPort))
	log.Println("search tcp/udp/icmp entity for v6hash:", v6hash)
	newENObj, found := nat46Table.Load(v6hash)
	if found {
		log.Println("ok, found it.")
		newEN = newENObj.(*Nat64TableEntity)
		newEN.lastTime = time.Now()
		return newEN
	} else {
		log.Println("not found ,abort!")
		return nil
	}
}

func getNatDst4To6(pkt *packet.Packet) *Nat64TableEntity {
	var v4hash string
	ipv4 := pkt.GetIPv4NoCheck()
	arp := pkt.GetARPNoCheck()
	if packet.SwapBytesUint16(arp.Operation) == packet.ARPRequest {
		//new nat46 arp session,setup a new Nat64TableEntity.
		return setupNewIcmpV4EN(*pkt)
	} else if packet.SwapBytesUint16(arp.Operation) == packet.ARPReply {
		v4hash = CalculatePktHash(types.ICMPv6Number, types.ArrayToIPv4(arp.SPA).String(), 0)
	} else {
		//arp/icmp type in hash is ICMPv6Number.
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
	nat46EN, ok := nat46Table.Load(v4hash)
	//}
	if ok {
		log.Println("found:", nat46EN.(*Nat64TableEntity))
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
		log.Println("send new NS request pkt:", sendNewNSForIPv6Target(newIcmpEn))
		//wait for NA pkt.
		v4hashIcmp := CalculatePktHash(types.ICMPv6Number, ipv4.SrcAddr.String(), 0)
		found := false
		zeroMac := types.MACAddress{0, 0, 0, 0, 0, 0}
		var icmpEn *Nat64TableEntity
		for i := 1; i < 10; i++ {
			time.Sleep(time.Duration(100) * time.Millisecond)
			obj, ok := nat46Table.Load(v4hashIcmp)
			if ok && obj.(*Nat64TableEntity).v6NodeMAC != zeroMac {
				icmpEn = obj.(*Nat64TableEntity)
				log.Println("ok,got in", i*100, "Millisecond:", icmpEn)
				found = true
				break
			}
		}
		if !found {
			log.Println("waited for 1 second,no luck,abort.")
			return nil
		} else {
			//new tcp/udp/icmp entity
			sport, dport := uint16(0), uint16(0)
			switch ipv4.NextProtoID {
			case types.TCPNumber:
				sport = packet.SwapBytesUint16(pkt.GetTCPForIPv4().SrcPort)
				dport = packet.SwapBytesUint16(pkt.GetTCPForIPv4().DstPort)
			case types.UDPNumber:
				sport = packet.SwapBytesUint16(pkt.GetUDPForIPv4().SrcPort)
				dport = packet.SwapBytesUint16(pkt.GetUDPForIPv4().DstPort)
			case types.ICMPNumber:
				sport = 0
				dport = 0
			}
			newEN := &Nat64TableEntity{
				proto:     ipv4.NextProtoID,
				v6SrcIP:   icmpEn.v6SrcIP,
				v6SrcPort: sport,
				v6DstIP:   icmpEn.v6DstIP,
				v6NodeMAC: icmpEn.v6NodeMAC,
				v6DstPort: dport,
				v4SrcIP:   icmpEn.v4SrcIP,
				v4SrcPort: sport,
				v4NodeMAC: icmpEn.v4NodeMAC,
				v4DstIP:   icmpEn.v4DstIP,
				v4DstPort: dport,
				lastTime:  time.Now(),
			}
			//save
			log.Println("new tcp/udp/icmp nat64entity.")
			log.Println("save v4hash:", v4hash)
			nat46Table.Store(v4hash, newEN)
			//on v4nat64table ,treat arp/icmp type as types.ICMPv6Number. type TCP/UDP are the same code.
			v6hash := CalculatePktHash(int(ipv4.NextProtoID), newEN.v6DstIP.String(), newEN.v6DstPort)
			log.Println("and v6hash:", v6hash)
			nat46Table.Store(v6hash, newEN)
			//log.Println("stored v4 mac:", newEN.v4NodeMAC)
			return newEN
		}
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
	//may be a arp pkt or a ip pkt.
	var v4SrcIP, v4DstIP types.IPv4Address
	var ipv6Src, ipv6Dst types.IPv6Address
	arp := pkt.GetARPNoCheck()
	if arp != nil && packet.SwapBytesUint16(arp.Operation) == packet.ARPRequest {
		v4SrcIP = types.ArrayToIPv4(arp.SPA)
		v4DstIP = types.ArrayToIPv4(arp.TPA)
	} else {
		v4SrcIP = pkt.GetIPv4NoCheck().SrcAddr
		v4DstIP = pkt.GetIPv4NoCheck().DstAddr
	}
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
		v6NodeMAC: pkt.Ether.DAddr,
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
