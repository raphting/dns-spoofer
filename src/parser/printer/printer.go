package printer

import (
  "fmt"
  "parser/dns"
)

func ID(d dns.DNS) {
  fmt.Println("ID:", d.GetID())
}

func QR(d dns.DNS) {
  fmt.Printf("QR: ")
  if d.GetQR() {
    fmt.Println("1 Response")
  } else {
    fmt.Println("0 Query")
  }
}

func OPCODE(d dns.DNS) {
  fmt.Printf("OPCODE: ")
  switch d.GetOPCODE() {
    case 0: fmt.Println("0 QUERY")
    case 1: fmt.Println("1 IQUERY")
    default: fmt.Println(">1 RESERVED")
  }
}

func AA(d dns.DNS) {
  fmt.Printf("AA: ")
  if d.GetAA() {
    fmt.Println("Authorative")
  } else {
    fmt.Println("Non authorative")
  }
}

func TC(d dns.DNS) {
  fmt.Printf("TC: ")
  if d.GetTC() {
    fmt.Println("Truncated")
  } else {
    fmt.Println("Not truncated")
  }
}

func RD(d dns.DNS) {
  fmt.Printf("RD: ")
  if d.GetRD() {
    fmt.Println("Recursion Desired")
  } else {
    fmt.Println("Recursion not Desired")
  }
}

func RA(d dns.DNS) {
  fmt.Printf("RA: ")
  if d.GetRA() {
		fmt.Println("Recursion Available")
	} else {
		fmt.Println("Recursion not Available")
	}
}

func Z(d dns.DNS) {
  fmt.Printf("Z: ")
  if d.GetZ() == 0 {
  	fmt.Println("Reserved")
  } else {
  	fmt.Printf("Should be 0 but is %d \n", d.GetZ())
  }
}

func RCODE(d dns.DNS) {
  fmt.Printf("RCODE: ")
	switch d.GetRCODE() {
		case 0:	fmt.Println("0 No error condition")
		case 1:	fmt.Println("1 Format error")
		case 2: fmt.Println("2 Server failure")
		case 3: if d.GetAA() {
              fmt.Println("3 Name error")
            } else {
              fmt.Println("3 ERROR! Only meaningful if AA is set")
            }
		case 4:	fmt.Println("4 Not implemented")
		case 5:	fmt.Println("5 Refused")
		default: fmt.Println(">5 Reserved for future use")
	}
}

func QDCOUNT(d dns.DNS) {
    fmt.Println("QDCOUNT:", d.GetQDCOUNT())
}

func ANCOUNT(d dns.DNS) {
    fmt.Println("ANCOUNT:", d.GetANCOUNT())
}

func NSCOUNT(d dns.DNS) {
    fmt.Println("NSCOUNT:", d.GetNSCOUNT())
}

func ARCOUNT(d dns.DNS) {
    fmt.Println("ARCOUNT:", d.GetARCOUNT())
}

func QNAME(d dns.DNS, num uint16) {
  qname, err := d.GetQNAME(num)
  if err != nil {
    fmt.Println(err.Error(), "\n")
    return
  }
  fmt.Println("QNAME: ", qname)
}

func QTYPE(d dns.DNS, num uint16) {
  field, err := d.GetQTYPE(num)

  if err != nil {
    fmt.Println(err.Error(), "\n")
    return
  }

  fmt.Printf("QTYPE: ")
  switch field {
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
    case 28:	fmt.Println("AAAA")
    case 252: fmt.Println("AXFR")
    case 253: fmt.Println("MAILB")
    case 254: fmt.Println("MAILA")
    case 255: fmt.Println("*")
    default:	fmt.Printf("NOT VALID %d \n", field)
  }
}

func QCLASS(d dns.DNS, num uint16) {
  field, err := d.GetQCLASS(num)

  if err != nil {
    fmt.Println(err.Error(), "\n")
    return
  }

  fmt.Printf("QCLASS: ")
  switch field {
    case 1:		fmt.Println("IN")
    case 2:		fmt.Println("CS")
    case 3:		fmt.Println("CH")
    case 4:		fmt.Println("HS")
    case 255:	fmt.Println("*")
    default:	fmt.Printf("NOT VALID %d \n", field)
  }
}
