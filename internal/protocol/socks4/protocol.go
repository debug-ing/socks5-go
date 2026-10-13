package socks4

import (
	"encoding/binary"
	"io"
	"net"
	"strings"
	"time"
)

const (
	socksVersion = 4
	cmdConnect   = 1
	replyGranted = 90
	replyFailed  = 91
)

type Socks4 struct {
	Dialer net.Dialer
}

func (s *Socks4) HandleConnection(client net.Conn) {
	defer client.Close()

	_ = client.SetDeadline(time.Now().Add(15 * time.Second))

	var header [8]byte
	if _, err := io.ReadFull(client, header[:]); err != nil {
		return
	}

	if header[0] != socksVersion || header[1] != cmdConnect {
		writeReply(client, replyFailed, 0, nil)
		return
	}

	port := binary.BigEndian.Uint16(header[2:4])
	if port == 0 {
		writeReply(client, replyFailed, 0, nil)
		return
	}

	ip := net.IPv4(header[4], header[5], header[6], header[7])

	_, err := readCString(client, 255)
	if err != nil {
		writeReply(client, replyFailed, 0, nil)
		return
	}

	host := ip.String()

	// SOCKS4a: 0.0.0.x, where x != 0, signals a domain name.
	if ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0 {
		host, err = readCString(client, 255)
		if err != nil || host == "" {
			writeReply(client, replyFailed, 0, nil)
			return
		}

		// Reject control characters in the supplied hostname.
		if strings.ContainsAny(host, "\r\n\t ") {
			writeReply(client, replyFailed, 0, nil)
			return
		}
	}

	target := net.JoinHostPort(host, itoa(int(port)))

	_ = client.SetDeadline(time.Time{})

	upstream, err := s.Dialer.Dial("tcp", target)
	if err != nil {
		writeReply(client, replyFailed, 0, nil)
		return
	}
	defer upstream.Close()

	writeReply(client, replyGranted, 0, net.IPv4zero)

	done := make(chan struct{}, 2)

	go func() {
		_, _ = io.Copy(upstream, client)
		if c, ok := upstream.(*net.TCPConn); ok {
			_ = c.CloseWrite()
		}
		done <- struct{}{}
	}()

	go func() {
		_, _ = io.Copy(client, upstream)
		if c, ok := client.(*net.TCPConn); ok {
			_ = c.CloseWrite()
		}
		done <- struct{}{}
	}()

	<-done
	_ = client.Close()
	_ = upstream.Close()
	<-done
}

func writeReply(conn net.Conn, status byte, port uint16, ip net.IP) {
	reply := make([]byte, 8)
	reply[1] = status
	binary.BigEndian.PutUint16(reply[2:4], port)

	if ip4 := ip.To4(); ip4 != nil {
		copy(reply[4:8], ip4)
	}

	_, _ = conn.Write(reply)
}

func readCString(conn net.Conn, max int) (string, error) {
	buf := make([]byte, 0, 32)

	for i := 0; i < max; i++ {
		var b [1]byte
		if _, err := io.ReadFull(conn, b[:]); err != nil {
			return "", err
		}
		if b[0] == 0 {
			return string(buf), nil
		}
		buf = append(buf, b[0])
	}

	return "", io.ErrShortBuffer
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [5]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
