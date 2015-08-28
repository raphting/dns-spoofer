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

	stream := make([]byte, 4096)
	for {
		_, _, err := ln.ReadFrom(stream)

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

		printer.QNAME(*myPacket, 0)
		printer.QTYPE(*myPacket, 0)
		printer.QCLASS(*myPacket, 0)



/*
//Parse Question Section
		for i := 0; i < int(qdcount); i++ {
			fmt.Printf("QNAME: ")

			for {
				byteCounter++
				var qnameSize int = int(stream[byteCounter])

				if(qnameSize == 0) {break}

				for j := 0; j < qnameSize; j++ {
					byteCounter++
					fmt.Printf(string(stream[byteCounter]))
				}

				fmt.Printf(".")
			}

			fmt.Println("")

			fmt.Printf("QTYPE: ")
			var qtype uint16 = uint16(stream[byteCounter+1]) << 8 | uint16(stream[byteCounter+2])
			switch qtype {
				case 1:		fmt.Println("A")
				case 2:		fmt.Println("NS")
				case 3:		fmt.Println("MD")
				case 4:		fmt.Println("MF")
				case 5:		fmt.Println("CNAME")
				case 6:		fmt.Println("SOA")
				case 7:		fmt.Println("MB")
				case 8:		fmt.Println("MG")
				case 9:		fmt.Println("MR")
				case 10:	fmt.Println("NULL")
				case 11:	fmt.Println("WKS")
				case 12:	fmt.Println("PTR")
				case 13:	fmt.Println("HINFO")
				case 14:	fmt.Println("MINFO")
				case 15:	fmt.Println("MX")
				case 16:	fmt.Println("TXT")
				case 252: fmt.Println("AXFR")
				case 253: fmt.Println("MAILB")
				case 254: fmt.Println("MAILA")
				case 255: fmt.Println("*")
				default:	fmt.Printf("NOT VALID %d \n", qtype)
			}

			fmt.Printf("QCLASS: ")
			var qclass uint16 = uint16(stream[byteCounter+3]) << 8 | uint16(stream[byteCounter+4])
			switch qclass {
				case 1:		fmt.Println("IN")
				case 2:		fmt.Println("CS")
				case 3:		fmt.Println("CH")
				case 4:		fmt.Println("HS")
				case 255:	fmt.Println("*")
				default:	fmt.Printf("NOT VALID %d \n", qclass)
			}

			byteCounter += 4
		}

*/


	}
}
