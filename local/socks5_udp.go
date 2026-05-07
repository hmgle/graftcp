package local

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

const (
	socks5Version       = 0x05
	socks5AuthNone      = 0x00
	socks5AuthUserPass  = 0x02
	socks5AuthNoAccept  = 0xff
	socks5CmdUDP        = 0x03
	socks5AtypIPv4      = 0x01
	socks5AtypDomain    = 0x03
	socks5AtypIPv6      = 0x04
	socks5HandshakeTime = 10 * time.Second
)

type socks5UDPForwarder struct {
	proxy       *UDPProxy
	clientAddr  *net.UDPAddr
	tokenIP     net.IP
	destUDPAddr *net.UDPAddr
	association *socks5UDPAssociation
}

type socks5UDPAssociation struct {
	tcp       net.Conn
	udp       *net.UDPConn
	relayAddr *net.UDPAddr
}

func (l *Local) newSocks5UDPForwarder(proxy *UDPProxy, clientAddr *net.UDPAddr, tokenIP net.IP, destAddr string) (*socks5UDPForwarder, error) {
	if l.socks5Addr == "" {
		return nil, fmt.Errorf("SOCKS5 proxy is not configured")
	}
	destUDPAddr, err := net.ResolveUDPAddr("udp", destAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve UDP destination %q: %w", destAddr, err)
	}
	association, err := newSocks5UDPAssociation(l.socks5Addr, l.socks5Username, l.socks5Password)
	if err != nil {
		return nil, err
	}
	forwarder := &socks5UDPForwarder{
		proxy:       proxy,
		clientAddr:  cloneUDPAddr(clientAddr),
		tokenIP:     cloneIP(tokenIP),
		destUDPAddr: destUDPAddr,
		association: association,
	}
	go forwarder.readLoop()
	return forwarder, nil
}

func (f *socks5UDPForwarder) Write(payload []byte) error {
	packet, err := encodeSocks5UDPDatagram(f.destUDPAddr, payload)
	if err != nil {
		return err
	}
	_, err = f.association.udp.WriteToUDP(packet, f.association.relayAddr)
	return err
}

func (f *socks5UDPForwarder) Close() error {
	return f.association.Close()
}

func (f *socks5UDPForwarder) readLoop() {
	buf := make([]byte, udpPacketMaxSize)
	for {
		if err := f.association.udp.SetReadDeadline(time.Now().Add(udpSessionReadLimit)); err != nil {
			return
		}
		n, _, err := f.association.udp.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if !isClosedNetworkError(err) {
				log.Errorf("SOCKS5 UDP read err: %s", err.Error())
			}
			return
		}
		payload, err := parseSocks5UDPDatagram(buf[:n])
		if err != nil {
			log.Errorf("SOCKS5 UDP response parse err: %s", err.Error())
			continue
		}
		if err := f.proxy.sendToClient(payload, f.tokenIP, f.clientAddr); err != nil {
			log.Errorf("SOCKS5 UDP response write to %s err: %s", f.clientAddr.String(), err.Error())
			return
		}
	}
}

func (a *socks5UDPAssociation) Close() error {
	var closeErr error
	if a == nil {
		return nil
	}
	if a.udp != nil {
		if err := a.udp.Close(); err != nil && closeErr == nil {
			closeErr = err
		}
	}
	if a.tcp != nil {
		if err := a.tcp.Close(); err != nil && closeErr == nil {
			closeErr = err
		}
	}
	return closeErr
}

func newSocks5UDPAssociation(proxyAddr, username, password string) (*socks5UDPAssociation, error) {
	tcpConn, err := net.DialTimeout("tcp", proxyAddr, socks5HandshakeTime)
	if err != nil {
		return nil, fmt.Errorf("dial SOCKS5 proxy %q: %w", proxyAddr, err)
	}
	if err := tcpConn.SetDeadline(time.Now().Add(socks5HandshakeTime)); err != nil {
		_ = tcpConn.Close()
		return nil, err
	}
	if err := socks5NegotiateAuth(tcpConn, username, password); err != nil {
		_ = tcpConn.Close()
		return nil, err
	}
	udpConn, err := listenSocks5UDP(proxyAddr)
	if err != nil {
		_ = tcpConn.Close()
		return nil, fmt.Errorf("create SOCKS5 UDP socket: %w", err)
	}
	relayAddr, err := socks5UDPAssociate(tcpConn, proxyAddr, udpConn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		_ = udpConn.Close()
		_ = tcpConn.Close()
		return nil, err
	}
	if err := tcpConn.SetDeadline(time.Time{}); err != nil {
		_ = udpConn.Close()
		_ = tcpConn.Close()
		return nil, err
	}
	return &socks5UDPAssociation{
		tcp:       tcpConn,
		udp:       udpConn,
		relayAddr: relayAddr,
	}, nil
}

func listenSocks5UDP(proxyAddr string) (*net.UDPConn, error) {
	network := "udp"
	if tcpAddr, err := net.ResolveTCPAddr("tcp", proxyAddr); err == nil && tcpAddr.IP != nil {
		if tcpAddr.IP.To4() != nil {
			network = "udp4"
		} else if tcpAddr.IP.To16() != nil {
			network = "udp6"
		}
	}
	return net.ListenUDP(network, nil)
}

func socks5NegotiateAuth(conn net.Conn, username, password string) error {
	methods := []byte{socks5AuthNone}
	if username != "" {
		methods = append(methods, socks5AuthUserPass)
	}
	req := []byte{socks5Version, byte(len(methods))}
	req = append(req, methods...)
	if _, err := conn.Write(req); err != nil {
		return err
	}

	var resp [2]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return err
	}
	if resp[0] != socks5Version {
		return fmt.Errorf("bad SOCKS5 auth version %d", resp[0])
	}
	switch resp[1] {
	case socks5AuthNone:
		return nil
	case socks5AuthUserPass:
		return socks5UsernamePasswordAuth(conn, username, password)
	case socks5AuthNoAccept:
		return fmt.Errorf("SOCKS5 proxy rejected all auth methods")
	default:
		return fmt.Errorf("SOCKS5 proxy selected unsupported auth method %d", resp[1])
	}
}

func socks5UsernamePasswordAuth(conn net.Conn, username, password string) error {
	if len(username) > 255 || len(password) > 255 {
		return fmt.Errorf("SOCKS5 username/password is too long")
	}
	req := []byte{0x01, byte(len(username))}
	req = append(req, username...)
	req = append(req, byte(len(password)))
	req = append(req, password...)
	if _, err := conn.Write(req); err != nil {
		return err
	}
	var resp [2]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return err
	}
	if resp[0] != 0x01 {
		return fmt.Errorf("bad SOCKS5 username/password auth version %d", resp[0])
	}
	if resp[1] != 0x00 {
		return fmt.Errorf("SOCKS5 username/password authentication failed")
	}
	return nil
}

func socks5UDPAssociate(conn net.Conn, proxyAddr string, bindAddr *net.UDPAddr) (*net.UDPAddr, error) {
	req, err := encodeSocks5UDPAssociateRequest(bindAddr)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}
	_, host, port, err := readSocks5Reply(conn)
	if err != nil {
		return nil, err
	}
	if isUnspecifiedHost(host) {
		if proxyHost, _, splitErr := net.SplitHostPort(proxyAddr); splitErr == nil {
			host = proxyHost
		}
	}
	return net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
}

// isUnspecifiedHost reports whether host is empty or refers to the IPv4/IPv6
// "any" address. The SOCKS5 spec lets relays advertise such addresses to mean
// "use the same host you connected to me on".
func isUnspecifiedHost(host string) bool {
	if host == "" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		return true
	}
	return false
}

func encodeSocks5UDPAssociateRequest(bindAddr *net.UDPAddr) ([]byte, error) {
	req := []byte{socks5Version, socks5CmdUDP, 0x00}
	port := 0
	atyp := byte(socks5AtypIPv4)
	addr := []byte{0x00, 0x00, 0x00, 0x00}
	if bindAddr != nil {
		port = bindAddr.Port
		if ip4 := bindAddr.IP.To4(); ip4 != nil {
			addr = ip4
		} else if ip16 := bindAddr.IP.To16(); ip16 != nil {
			atyp = socks5AtypIPv6
			addr = ip16
		} else if len(bindAddr.IP) != 0 {
			return nil, fmt.Errorf("invalid SOCKS5 UDP bind IP %q", bindAddr.IP.String())
		}
	}
	req = append(req, atyp)
	req = append(req, addr...)
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], uint16(port))
	req = append(req, portBuf[:]...)
	return req, nil
}

func readSocks5Reply(conn net.Conn) (byte, string, int, error) {
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return 0, "", 0, err
	}
	if header[0] != socks5Version {
		return 0, "", 0, fmt.Errorf("bad SOCKS5 reply version %d", header[0])
	}
	if header[1] != 0x00 {
		return 0, "", 0, fmt.Errorf("SOCKS5 UDP associate failed with reply %d", header[1])
	}

	host, err := readSocks5Address(conn, header[3])
	if err != nil {
		return 0, "", 0, err
	}
	var portBuf [2]byte
	if _, err := io.ReadFull(conn, portBuf[:]); err != nil {
		return 0, "", 0, err
	}
	return header[3], host, int(binary.BigEndian.Uint16(portBuf[:])), nil
}

func readSocks5Address(r io.Reader, atyp byte) (string, error) {
	switch atyp {
	case socks5AtypIPv4:
		var ip [4]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return "", err
		}
		return net.IP(ip[:]).String(), nil
	case socks5AtypIPv6:
		var ip [16]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return "", err
		}
		return net.IP(ip[:]).String(), nil
	case socks5AtypDomain:
		var lenBuf [1]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			return "", err
		}
		name := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(r, name); err != nil {
			return "", err
		}
		return string(name), nil
	default:
		return "", fmt.Errorf("unsupported SOCKS5 address type %d", atyp)
	}
}

func encodeSocks5UDPDatagram(dest *net.UDPAddr, payload []byte) ([]byte, error) {
	if dest == nil {
		return nil, fmt.Errorf("nil SOCKS5 UDP destination")
	}
	packet := []byte{0x00, 0x00, 0x00}
	if ip4 := dest.IP.To4(); ip4 != nil {
		packet = append(packet, socks5AtypIPv4)
		packet = append(packet, ip4...)
	} else if ip16 := dest.IP.To16(); ip16 != nil {
		packet = append(packet, socks5AtypIPv6)
		packet = append(packet, ip16...)
	} else {
		return nil, fmt.Errorf("invalid SOCKS5 UDP destination IP %q", dest.IP.String())
	}
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], uint16(dest.Port))
	packet = append(packet, portBuf[:]...)
	packet = append(packet, payload...)
	return packet, nil
}

func parseSocks5UDPDatagram(packet []byte) ([]byte, error) {
	if len(packet) < 4 {
		return nil, fmt.Errorf("short SOCKS5 UDP datagram")
	}
	if packet[0] != 0x00 || packet[1] != 0x00 {
		return nil, fmt.Errorf("bad SOCKS5 UDP reserved field")
	}
	if packet[2] != 0x00 {
		return nil, fmt.Errorf("fragmented SOCKS5 UDP datagram is unsupported")
	}
	offset := 4
	switch packet[3] {
	case socks5AtypIPv4:
		offset += net.IPv4len
	case socks5AtypIPv6:
		offset += net.IPv6len
	case socks5AtypDomain:
		if len(packet) < offset+1 {
			return nil, fmt.Errorf("short SOCKS5 UDP domain header")
		}
		offset += 1 + int(packet[offset])
	default:
		return nil, fmt.Errorf("unsupported SOCKS5 UDP address type %d", packet[3])
	}
	offset += 2
	if len(packet) < offset {
		return nil, fmt.Errorf("short SOCKS5 UDP address header")
	}
	payload := make([]byte, len(packet)-offset)
	copy(payload, packet[offset:])
	return payload, nil
}

func isClosedNetworkError(err error) bool {
	return errors.Is(err, net.ErrClosed)
}
