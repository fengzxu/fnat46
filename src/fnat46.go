package main

import (
	"bytes"
	"flag"
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
	"github.com/intel-go/nff-go/types"
	"log"
	"net"
)

var config *Nat46Config

func main() {

	v6port := flag.Uint("v6port", 0, "port for receiver and send pkt in IPv6.")
	v4port := flag.Uint("v4port", 1, "port for receiver and send pkt in IPv4.")
	v6pre := flag.String("v6pre", "6001:db8::", "IPv6 prefix to translate address ,end with '::' prefix len=96.")
	v6ip := flag.String("v6ip", "6001:db8::10", "IPv6 address for port used by IPv6 .")
	v4ip := flag.String("v4ip", "192.168.21.10", "IPv4 address for port used by IPv4 .")
	flag.Parse()

	//init ports and mem
	flow.CheckFatal(flow.SystemInit(nil))

	//init nat64 config
	initConfig(*v6port, *v4port, *v6pre, *v6ip, *v4ip)

	//init nat64 v6-v4 nat table
	initNat46Table()

	//init nat46 v4-v6 nat table
	initNat46Map()

	//remove expired statefull ipv4Dst map to release aviable ipv4&&port resource
	go RemoveExpiredIPv4Dst()

	//remove expired statefull nat64&&nat46 map to update new info about session
	go RemoveExpiredNatEntity()

	//now nat46
	flowIPv6portIn, err := flow.SetReceiver(config.v6port)
	flow.CheckFatal(err)
	flow.CheckFatal(flow.SetHandler(flowIPv6portIn, hanFunV6portIn, nil))
	flow.CheckFatal(flow.SetStopper(flowIPv6portIn))

	flowIPv4portIn, err := flow.SetReceiver(config.v4port)
	flow.CheckFatal(err)
	flow.CheckFatal(flow.SetHandler(flowIPv4portIn, hanFunV4portIn, nil))
	flow.CheckFatal(flow.SetStopper(flowIPv4portIn))

	flow.CheckFatal(flow.SystemStart())
}

func initConfig(v6port, v4port uint, v6pre, v6ip, v4ip string) {
	config = &Nat46Config{
		v6port:    uint16(v6port),
		v6portMac: flow.GetPortMACAddress(0),
		v6prefix:  IP2IPv6addr(net.ParseIP(v6pre).To16()),
		v6ip:      IP2IPv6addr(net.ParseIP(v6ip)),
		v4port:    uint16(v4port),
		v4portMAC: flow.GetPortMACAddress(1),
		v4ip:      IP2IPv4addr(net.ParseIP(v4ip)),
	}
	log.Println(config.String())
}

/**
Deal with 6-4 pkt translate
*/
func hanFunV6portIn(pkt *packet.Packet, context flow.UserContext) {
	pkt.ParseL3()
	ipv6 := pkt.GetIPv6NoCheck()
	if ipv6 == nil {
		//ipv4 pkt, forward to ipv4 port
		log.Println("got ipv4 pkt on ipv6 port ,drop.")
		return
	}
	pkt.ParseL4ForIPv6()
	switch ipv6.Proto {
	case types.ICMPv6Number:
		icmp6 := pkt.GetICMPForIPv6()
		pkt.ParseL7(types.ICMPv6Number)
		switch icmp6.Type {
		case types.ICMPv6NeighborSolicitation:
			dstAddr := pkt.GetICMPv6NeighborSolicitationMessage().TargetAddr
			if dstAddr == config.v6ip {
				log.Println("ns for me , now answer it...")
				answerNS4Me(pkt)
			} else if bytes.Compare(dstAddr[:12], config.v6prefix[:12]) == 0 {
				log.Println("ns for prefix, now generate ipv4 arp ...")
				dealPktIPv6NSonV6port(pkt)
			}
		case types.ICMPv6NeighborAdvertisement:
			dealPktNat46ArpResponse(pkt)
		case types.ICMPv6TypeEchoRequest:
			if ipv6.DstAddr == config.v6ip {
				log.Println("echo request for me on v6port, now answer it...")
				answerICMP6EchoReq4Me(pkt)
			} else {
				log.Println("got a icmp6 echo request pkt.")
				dealPktIPv6ToIPv4ICMP(pkt)
			}
		case types.ICMPv6TypeEchoResponse:
			if bytes.Compare(ipv6.DstAddr[:12], config.v6prefix[:12]) == 0 {
				log.Println("got a icmp6 echo response pkt.")
				dealPktIPv6ToIPv4ICMP(pkt)
			} else {
				return
			}
		}
	case types.TCPNumber:
		dealPktIPv6ToIPv4TCP(pkt)
	case types.UDPNumber:
		dealPktIPv6ToIPv4UDP(pkt)
	}
}

/**
Deal with 4-6 pkt translate
*/
func hanFunV4portIn(pkt *packet.Packet, context flow.UserContext) {
	pkt.ParseL3()
	arp := pkt.GetARPCheckVLAN()
	if arp != nil {
		switch packet.SwapBytesUint16(arp.Operation) {
		case packet.ARPRequest:
			//An arp request for me or ipv4 pool
			tpaIPv4 := types.ArrayToIPv4(arp.TPA)
			if tpaIPv4 == config.v4ip {
				answerPktIPv4ArpRequestForMe(pkt)
			} else if isNat46TarIPv4(tpaIPv4) {
				//An arp request for fake IPv4 on NAT46
				dealPktNat46ArpRequest(pkt)
			} else {
				//none business pkt,ignore it ...
				return
			}
		case packet.ARPReply:
			dealPktIPv4ArpReply(pkt)
		}
	}
	ipv4 := pkt.GetIPv4()
	if ipv4 != nil {
		pkt.ParseL4ForIPv4()
		switch ipv4.NextProtoID {
		case types.ICMPNumber:
			icmp4 := pkt.GetICMPForIPv4()
			switch icmp4.Type {
			case types.ICMPTypeEchoRequest: //init from ipv4 port
				if ipv4.DstAddr == config.v4ip {
					answerICMPEchoReqForMe(pkt)
				} else if isNat46TarIPv4(ipv4.DstAddr) {
					dealPktIPv4ToIPv6EchoRequest(pkt)
				} else {
					return
				}
			case types.ICMPTypeEchoResponse: //init from v6 port, got answer from v4 port
				if isNat46TarIPv4(ipv4.DstAddr) {
					dealPktIPv4ToIPv6EchoResponse(pkt)
				} else {
					return
				}
			}
		case types.TCPNumber:
			if isNat46TarIPv4(ipv4.DstAddr) {
				dealPktIPv4ToIPv6TCP(pkt)
			} else {
				return
			}
		case types.UDPNumber:
			if isNat46TarIPv4(ipv4.DstAddr) {
				dealPktIPv4ToIPv6UDP(pkt)
			} else {
				return
			}
		}
	} else {
		log.Println("got a none ipv4 pkt on ipv4 port,ignore it.")
	}
}