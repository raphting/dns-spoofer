package dns

import (
  "errors"
)

type DNS struct {
  aa, qr, ra, rd, tc bool
  opcode, rcode, z byte
  byteCounter uint16 //Keep track of position in packet stream
  ancount, arcount, id, nscount, qdcount uint16
  qds []qd
  ans []ar
  nss []ar
  ars []ar
}

type qd struct {
  qname string
  qtype, qclass uint16
}

type ar struct {
  qd
  artype, arclass, rdlength uint16
  ttl int32
}

func parse16Bit(msb byte, lsb byte) uint16 {
	return uint16(msb) << 8 | uint16(lsb)
}


/***********PARSER*************************/
func (d *DNS) parseID(id0, id1 byte) {
  d.id = parse16Bit(id0, id1)
}

func (d *DNS) parseQR(qr byte) {
  if qr >> 7 == 1 {
    d.qr = true
  } else {
    d.qr = false
  }
}

func (d *DNS) parseOPCODE(opcode byte) {
  d.opcode = opcode >> 3 & 0x0F
}

func (d *DNS) parseAA(aa byte) {
  if aa >> 2 & 1 == 1 {
    d.aa = true
  } else {
    d.aa = false
  }
}

func (d *DNS) parseTC(tc byte) {
  if tc >> 1 & 1 == 1 {
      d.tc = true
    } else {
      d.tc = false
    }
}

func (d *DNS) parseRD(rd byte) {
  if rd & 1 == 1 {
    d.rd = true
  } else {
    d.rd = false
  }
}

func (d *DNS) parseRA(ra byte) {
  if ra >> 7 & 1 == 1 {
    d.ra = true
  } else {
    d.ra = false
  }
}

func (d *DNS) parseZ(z byte) {
  d.z = z >> 4 & 0x07
}

func (d *DNS) parseRCODE(rcode byte) {
  d.rcode = rcode & 0x0F
}

func (d *DNS) parseQDCOUNT(b0, b1 byte) {
  d.qdcount = parse16Bit(b0, b1)
}

func (d *DNS) parseANCOUNT(b0, b1 byte) {
  d.ancount = parse16Bit(b0, b1)
}

func (d *DNS) parseNSCOUNT(b0, b1 byte) {
  d.nscount = parse16Bit(b0, b1)
}

func (d *DNS) parseARCOUNT(b0, b1 byte) {
  d.arcount = parse16Bit(b0, b1)
}

func parseXNAME(packet []byte, byteCounter uint16) (string, uint16) {
  qname := make([]byte, 0)

  for {
    byteCounter++
    var qnameSize int = int(packet[byteCounter])

    if(qnameSize == 0) {break}

    for j := 0; j < qnameSize; j++ {
      byteCounter++
      qname = append(qname, packet[byteCounter])
    }
    qname = append(qname, 46) //Add dot "." in ASCII 46
  }

  return string(qname), byteCounter
}



func (d *DNS) parseQ(packet []byte) {
  byteCounter := d.byteCounter
  for i := 0; i < int(d.qdcount); i++ {
    myqd := *new(qd)
    myqd.qname, byteCounter = parseXNAME(packet, byteCounter)
    myqd.qtype = parse16Bit(packet[byteCounter+1], packet[byteCounter+2])
    myqd.qclass = parse16Bit(packet[byteCounter+3], packet[byteCounter+4])

    d.qds = append(d.qds, myqd)
    byteCounter += 4
  }
  d.byteCounter = byteCounter
}


func (d *DNS) parseAR(packet []byte, field string) {
  byteCounter := d.byteCounter + 1
  myfield := *new(ar)

  var cnt uint16


/*
  switch field {
  case "an":
    myd = *
    cnt = d.ancount
  case "ns":
    myd = *d.nss
    cnt = d.nscount
  case "ar":
    myd = *d.ars
    cnt = d.arcount
  }
*/

  for i := 0; i < int(cnt); i++ {
    myqd := *new(qd)
    myqd.qname, byteCounter = parseXNAME(packet, byteCounter)
    myqd.qtype = parse16Bit(packet[byteCounter+1], packet[byteCounter+2])
    myqd.qclass = parse16Bit(packet[byteCounter+3], packet[byteCounter+4])

    myfield.qd = myqd
    d.ans = append(d.ans, myfield)
    byteCounter += 4
  }
  d.byteCounter = byteCounter
}

/***********GETTER*************************/
func (d DNS) GetID() uint16 {
  return d.id
}

func (d DNS) GetQR() bool {
  return d.qr
}

func (d DNS) GetOPCODE() byte {
  return d.opcode
}

func (d DNS) GetAA() bool {
  return d.aa
}

func (d DNS) GetTC() bool {
  return d.tc
}

func (d DNS) GetRD() bool {
  return d.rd
}

func (d DNS) GetRA() bool {
  return d.ra
}

func (d DNS) GetZ() byte {
  return d.z
}

func (d DNS) GetRCODE() byte {
  return d.rcode
}

func (d DNS) GetQDCOUNT() uint16 {
  return d.qdcount
}

func (d DNS) GetANCOUNT() uint16 {
  return d.ancount
}

func (d DNS) GetNSCOUNT() uint16 {
  return d.nscount
}

func (d DNS) GetARCOUNT() uint16 {
  return d.arcount
}

func (d DNS) GetQNAME(num int) (string, error) {
  if int(num) > len(d.qds) - 1 {
    return "", errors.New("dns: out of bounds for qname field.")
  }
  return d.qds[num].qname, nil
}

func (d DNS) GetQTYPE(num int) (uint16, error) {
  if int(num) > len(d.qds) - 1 {
    return 0, errors.New("dns: out of bounds for qtype field.")
  }
  return d.qds[num].qtype, nil
}

func (d DNS) GetQCLASS(num int) (uint16, error) {
  if int(num) > len(d.qds) - 1 {
    return 0, errors.New("dns: out of bounds for qtype field.")
  }
  return d.qds[num].qclass, nil
}

func (d DNS) GetANNAME(num int) (string, error) {
  if int(num) > len(d.qds) - 1 {
    return "", errors.New("dns: out of bounds for qname field.")
  }
  return d.ans[num].qname, nil
}

func (d DNS) GetNSNAME(num int) (string, error) {
  if int(num) > len(d.qds) - 1 {
    return "", errors.New("dns: out of bounds for qname field.")
  }
  return d.nss[num].qname, nil
}

func (d DNS) GetARNAME(num int) (string, error) {
  if int(num) > len(d.qds) - 1 {
    return "", errors.New("dns: out of bounds for qname field.")
  }
  return d.ars[num].qname, nil
}

func Splitter(packet []byte) *DNS {
  pack := new(DNS)
  pack.parseID(packet[0], packet[1])
  pack.parseQR(packet[2])
  pack.parseOPCODE(packet[2])
  pack.parseAA(packet[2])
  pack.parseTC(packet[2])
  pack.parseRD(packet[2])
  pack.parseRA(packet[3])
  pack.parseZ(packet[3])
  pack.parseRCODE(packet[3])
  pack.parseQDCOUNT(packet[4], packet[5])
  pack.parseANCOUNT(packet[6], packet[7])
  pack.parseNSCOUNT(packet[8], packet[9])
  pack.parseARCOUNT(packet[10], packet[11])
  pack.byteCounter = 11 //We processed 11 bytes now

  pack.parseQ(packet)
  pack.parseAR(packet, "an")
  pack.parseAR(packet, "ns")
  pack.parseAR(packet, "ar")


  return pack
}
