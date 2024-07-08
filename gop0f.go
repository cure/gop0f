package gop0f

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
)

// Ported from p0f/api.h
const (
	P0F_STATUS_BADQUERY = 0x00
	P0F_STATUS_OK       = 0x10
	P0F_STATUS_NOMATCH  = 0x20
	P0F_ADDR_IPV4       = 0x04
	P0F_ADDR_IPV6       = 0x06
	P0F_STR_MAX         = 31
	P0F_MATCH_FUZZY     = 0x01
	P0F_MATCH_GENERIC   = 0x02
)

var (
	// The doc (https://lcamtuf.coredump.cx/p0f3/) says this should be network
	// (i.e. big) endian, but that appears to be incorrect, it needs to be little
	// endian, at least when the p0f service runs on a little-endian system.
	P0F_QUERY_MAGIC = [...]byte{0x01, 0x46, 0x30, 0x50} //0x50304601
	P0F_RESP_MAGIC  = [...]byte{0x02, 0x46, 0x30, 0x50} //0x50304602
)

type GoP0f struct {
	conn   net.Conn
	socket string
}

type P0fQuery struct {
	Magic    [4]byte  // Must be P0F_QUERY_MAGIC
	AddrType byte     // P0F_ADDR_*
	Addr     [16]byte // IP address (big endian left align)
}

type P0fResponse struct {
	Magic      uint32                // Must be P0F_RESP_MAGIC
	Status     uint32                // P0F_STATUS_*
	FirstSeen  uint32                // First seen (unix time)
	LastSeen   uint32                // Last seen (unix time)
	TotalCount uint32                // Total connections seen
	UptimeMin  uint32                // Last uptime (minutes)
	UpModDays  uint32                // Uptime modulo (days)
	LastNat    uint32                // NAT / LB last detected (unix time)
	LastChg    uint32                // OS chg last detected (unix time)
	Distance   uint16                // System distance
	BadSw      byte                  // Host is lying about U-A / Server
	OsMatchQ   byte                  // Match quality
	OsName     [P0F_STR_MAX + 1]byte // Name of detected OS
	OsFlavor   [P0F_STR_MAX + 1]byte // Flavor of detected OS
	HttpName   [P0F_STR_MAX + 1]byte // Name of detected HTTP app
	HttpFlavor [P0F_STR_MAX + 1]byte // Flavor of detected HTTP app
	LinkType   [P0F_STR_MAX + 1]byte // Link type
	Language   [P0F_STR_MAX + 1]byte // Language
}

func New(sock string) (p0f *GoP0f, err error) {
	p0f = &GoP0f{
		socket: sock,
	}
	//TODO: Check file before exists
	p0f.conn, err = net.Dial("unix", p0f.socket)
	if err != nil {
		return
	}

	return
}

func (p0f *GoP0f) Close() {
	p0f.conn.Close()
}

func (p0f *GoP0f) Query(srcAddr netip.Addr) (output string, err error) {
	var resp P0fResponse
	q := newP0fQuery(srcAddr)
	//fmt.Printf("Sending MAGIC %#08x\n", q.Magic)
	//fmt.Printf("%+x\n", q)
	err = binary.Write(p0f.conn, binary.BigEndian, q)
	if err != nil {
		return
	}

	var n int
	readbuf := make([]byte, 1048)
	n, err = p0f.conn.Read(readbuf[:])
	if err != nil {
		return
	}
	//fmt.Printf("Client got: %+v\n", readbuf[0:n])
	buf := bytes.NewReader(readbuf[0:n])
	err = binary.Read(buf, binary.LittleEndian, &resp)
	if err != nil {
		output = fmt.Sprintf("%+v", err)
		return
	}
	if resp.Magic != binary.LittleEndian.Uint32(P0F_RESP_MAGIC[:]) {
		output = fmt.Sprintf("Invalid response magic field: %x", resp.Magic)
		return
	}
	if resp.Status != P0F_STATUS_OK {
		if resp.Status == P0F_STATUS_BADQUERY {
			output = "Bad query"
		} else if resp.Status == P0F_STATUS_NOMATCH {
			output = "No match"
		} else {
			output = "Unknown error"
		}
		return
	}
	//fmt.Printf("%#v\n", resp)
	//fmt.Printf("%#v\n", resp.Magic)

	n = bytes.IndexByte(resp.OsName[:], 0)
	output += fmt.Sprintf("%s", string(resp.OsName[:n]))
	n = bytes.IndexByte(resp.OsFlavor[:], 0)
	if n > 0 {
		output += fmt.Sprintf(" %s", string(resp.OsFlavor[:n]))
	}
	if resp.OsMatchQ == P0F_MATCH_FUZZY {
		output += " [fuzzy]"
	} else if resp.OsMatchQ == P0F_MATCH_GENERIC {
		output += " [generic]"
	}
	return
}

func newP0fQuery(addr netip.Addr) *P0fQuery {
	q := &P0fQuery{
		Magic: P0F_QUERY_MAGIC,
	}
	if addr.Is4() {
		q.AddrType = P0F_ADDR_IPV4
	} else {
		q.AddrType = P0F_ADDR_IPV6
	}
	copy(q.Addr[:], addr.AsSlice())
	return q
}
