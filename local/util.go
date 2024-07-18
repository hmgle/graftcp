package local

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
)

// See https://man7.org/linux/man-pages/man7/sock_diag.7.html
// IPv4 and IPv6 sockets
//
//	For IPv4 and IPv6 sockets, the request is represented in the
//	following structure:
//
//	    struct inet_diag_req_v2 {
//	        __u8    sdiag_family;
//	        __u8    sdiag_protocol;
//	        __u8    idiag_ext;
//	        __u8    pad;
//	        __u32   idiag_states;
//	        struct inet_diag_sockid id;
//	    };
//
//	where struct inet_diag_sockid is defined as follows:
//
//	    struct inet_diag_sockid {
//	        __be16  idiag_sport;
//	        __be16  idiag_dport;
//	        __be32  idiag_src[4];
//	        __be32  idiag_dst[4];
//	        __u32   idiag_if;
//	        __u32   idiag_cookie[2];
//	    };
//
//	The response to a query for IPv4 or IPv6 sockets is represented
//	as an array of
//
//	    struct inet_diag_msg {
//	        __u8    idiag_family;
//	        __u8    idiag_state;
//	        __u8    idiag_timer;
//	        __u8    idiag_retrans;
//
//	        struct inet_diag_sockid id;
//
//	        __u32   idiag_expires;
//	        __u32   idiag_rqueue;
//	        __u32   idiag_wqueue;
//	        __u32   idiag_uid;
//	        __u32   idiag_inode;
//	    };
type (
	inetDiagReqV2 struct {
		SdiagFamily   uint8
		SdiagProtocol uint8
		IdiagExt      uint8
		Pad           uint8
		IdiagStates   uint32

		IdiagSport  uint16
		IdiagDport  uint16
		IdiagSrc    net.IP
		IdiagDst    net.IP
		IdiagIf     uint32
		IdiagCookie [2]uint32
	}
	inetDiagMSG struct {
		Family  byte
		State   byte
		Timer   byte
		ReTrans byte

		SrcPort [2]byte
		DstPort [2]byte
		Src     [16]byte
		Dst     [16]byte
		If      uint32
		Cookie  [2]uint32

		Expires uint32
		RQueue  uint32
		WQueue  uint32
		UID     uint32
		INode   uint32
	}
)

// socket diags related
const (
	SOCK_DIAG_BY_FAMILY = 20         /* linux.sock_diag.h */
	TCPDIAG_NOCOOKIE    = 0xFFFFFFFF /* TCPDIAG_NOCOOKIE in net/ipv4/tcp_diag.h*/
	sizeofInetDiagMSG   = 0x38
)

type writeBuffer struct {
	Bytes []byte
	pos   int
}

func (b *writeBuffer) Next(n int) []byte {
	s := b.Bytes[b.pos : b.pos+n]
	b.pos += n
	return s
}

func (req inetDiagReqV2) marshal() []byte {
	b := writeBuffer{Bytes: make([]byte, sizeofInetDiagMSG)}

	nlenc.PutUint8(b.Next(1), req.SdiagFamily)
	nlenc.PutUint8(b.Next(1), req.SdiagProtocol)
	nlenc.PutUint8(b.Next(1), req.IdiagExt)
	nlenc.PutUint8(b.Next(1), req.Pad)
	nlenc.PutUint32(b.Next(4), req.IdiagStates)

	binary.BigEndian.PutUint16(b.Next(2), req.IdiagSport)
	binary.BigEndian.PutUint16(b.Next(2), req.IdiagDport)

	copy(b.Next(16), req.IdiagSrc[:])
	copy(b.Next(16), req.IdiagDst[:])
	nlenc.PutUint32(b.Next(4), req.IdiagIf)
	nlenc.PutUint32(b.Next(4), req.IdiagCookie[0])
	nlenc.PutUint32(b.Next(4), req.IdiagCookie[1])

	return b.Bytes
}

func getInodeByAddrs(localAddr, remoteAddr *net.TCPAddr, isTCP6 bool) (inode string, err error) {
	var (
		family   uint8
		localIP  net.IP
		remoteIP net.IP
	)
	if isTCP6 {
		family = syscall.AF_INET6
		localIP = localAddr.IP.To16()
		remoteIP = remoteAddr.IP.To16()
	} else {
		family = syscall.AF_INET
		localIP = localAddr.IP.To4()
		remoteIP = remoteAddr.IP.To4()
	}
	req := &inetDiagReqV2{
		SdiagFamily:   family,
		SdiagProtocol: syscall.IPPROTO_TCP,
		IdiagStates:   0xffffffff,
		IdiagSport:    uint16(localAddr.Port),
		IdiagDport:    uint16(remoteAddr.Port),
		IdiagSrc:      localIP,
		IdiagDst:      remoteIP,
		IdiagIf:       0,
		IdiagCookie:   [2]uint32{TCPDIAG_NOCOOKIE, TCPDIAG_NOCOOKIE},
	}
	reqMsg := netlink.Message{
		Header: netlink.Header{
			Type:  SOCK_DIAG_BY_FAMILY,
			Flags: netlink.Request | netlink.Dump,
		},
		Data: req.marshal(),
	}
	c, err := netlink.Dial(syscall.NETLINK_INET_DIAG, nil)
	if err != nil {
		return
	}
	defer c.Close()
	respMsg, err := c.Execute(reqMsg)
	if err != nil {
		return
	}
	for _, msg := range respMsg {
		if len(msg.Data) < sizeofInetDiagMSG {
			continue
		}
		response := (*inetDiagMSG)(unsafe.Pointer(&msg.Data[0]))
		return strconv.FormatUint(uint64(response.INode), 10), nil
	}
	return "", fmt.Errorf("no inode for [%s %s]", localAddr.String(), remoteAddr.String())
}

func hasIncludeInode(pid, inode string) bool {
	pidInt, _ := strconv.Atoi(pid)
	if pidInt < 1 {
		return false
	}
	fds, _ := filepath.Glob("/proc/" + pid + "/fd/[0-9]*")
	for _, fd := range fds {
		link, _ := os.Readlink(fd)
		if strings.Contains(link, "socket:["+inode+"]") {
			return true
		}
	}
	if len(fds) == 0 {
		tidsFds, _ := filepath.Glob("/proc/[0-9]*/task/" + pid + "/fd/[0-9]*")
		for _, fd := range tidsFds {
			link, _ := os.Readlink(fd)
			if strings.Contains(link, "socket:["+inode+"]") {
				return true
			}
		}
	}
	return false
}
