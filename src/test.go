package main

import (
	"encoding/hex"
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
	"log"
)

func main() {
	flow.CheckFatal(flow.SystemInit(nil))
	//flowIPv6portIn, err := flow.SetReceiver(0)
	//flow.CheckFatal(err)
	//flow.CheckFatal(flow.SetHandler(flowIPv6portIn, testFunV6portIn, nil))
	//flow.CheckFatal(flow.SetStopper(flowIPv6portIn))

	flowIPv4portIn, err := flow.SetReceiver(1)
	flow.CheckFatal(err)
	flow.CheckFatal(flow.SetHandler(flowIPv4portIn, testFunV4portIn, nil))
	flow.CheckFatal(flow.SetStopper(flowIPv4portIn))

	flow.CheckFatal(flow.SystemStart())
}

func testFunV4portIn(pkt *packet.Packet, context flow.UserContext) {
	log.Println("ok,got a whatever pkt ,now send my snmp pkt... ")
	newPkt, err := packet.NewPacket()
	if err != nil {
		log.Println("new pkt error:", err.Error())
		return
	}
	packet.GeneratePacketFromByte(newPkt, getBytes())
	newPkt.SendPacket(1)
}

func getBytes() []byte {
	hexstr := "00505624b411005056c000010800450000478ddb00008011016ec0a81501c0a8150be91e00a100331413302902010104067075626c6963a01c020432337d55020100020100300e300c06082b060102010101000500"
	bytes, err := hex.DecodeString(hexstr)
	if err == nil {
		//log.Println("pkt bytes len:", len(bytes))
		return bytes
	} else {
		log.Println("err:", err.Error())
		return []byte{}
	}
}

//func main() {
//	bytes := getBytes()
//	log.Println("pkt bytes len:", len(bytes))
//}
