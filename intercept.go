package main

import (
	"flag"
	"fmt"
	"net"
	"parser/dns"
	"parser/printer"
)

func parse16Bit(msb byte, lsb byte) uint16 {
	return uint16(msb) << 8 | uint16(lsb)
}

func main() {
portPtr := flag.String("p", ":2323", "Port beeing opened.")
flag.Parse()

port := *portPtr


	fmt.Println("Starting the DNS Spoofer")

	ln, err := net.ListenPacket("udp", port)
	defer ln.Close()

	if err != nil {
		fmt.Println("Something went wrong with opening the udp port", port)
		fmt.Println(err)
		return
	}

	fmt.Println("Listening on ", port)

	stream := make([]byte, 512)
	alices := make(map[uint16]string)
	for {
		_, extAddr, err := ln.ReadFrom(stream)

		if err != nil {
			fmt.Println(err)
			return
		}

		fmt.Println("--------------------")
		fmt.Println("Received DNS Packet:")
		fmt.Println("--------------------")


		myPacket := dns.Splitter(stream)

		printer.ID(*myPacket)
		printer.QR(*myPacket)
		printer.OPCODE(*myPacket)
		printer.AA(*myPacket)
		printer.TC(*myPacket)
		printer.RD(*myPacket)
		printer.RA(*myPacket)
		printer.Z(*myPacket)
		printer.RCODE(*myPacket)
		printer.QDCOUNT(*myPacket)
		printer.ANCOUNT(*myPacket)
		printer.NSCOUNT(*myPacket)
		printer.ARCOUNT(*myPacket)

		for i := 0; i < int(myPacket.GetQDCOUNT()); i++ {
			printer.QNAME(*myPacket, i)
			printer.QTYPE(*myPacket, i)
			printer.QCLASS(*myPacket, i)
		}

		for i := 0; i < int(myPacket.GetANCOUNT()); i++ {
			printer.ARNAME(*myPacket, i, "an")
			printer.ANTTL(*myPacket, i)
		}

		for i := 0; i < int(myPacket.GetNSCOUNT()); i++ {
			//printer.ARNAME(*myPacket, i, "ns")
		}

		for i := 0; i < int(myPacket.GetARCOUNT()); i++ {
			//printer.ARNAME(*myPacket, i, "ar")
		}

		if myPacket.GetQR() == false {
			google, _ := net.ResolveUDPAddr("udp4", "8.8.8.8:53")
			ln.WriteTo(stream, google)
			fmt.Println("Sent to google")
			alices[myPacket.GetID()] = extAddr.String()
		}

		if myPacket.GetQR() == true {
			_, ok := alices[myPacket.GetID()]
			if ok {
				aliceAddr, _ := net.ResolveUDPAddr("udp4", alices[myPacket.GetID()])
				delete(alices, myPacket.GetID())
				ln.WriteTo(stream, aliceAddr)
				fmt.Println("Sent to Alice")
			}
		}


	}
}
