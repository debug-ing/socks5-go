package internal

import (
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"time"
)

const (
	socksVersion       = 5
	authNone           = 0
	authUsernamePasswd = 2
	authNoAccept       = 0xFF

	cmdConnect = 1

	addrIPv4   = 1
	addrDomain = 3
	addrIPv6   = 4
)

type Request struct {
	Cmd      byte
	AddrType byte
	Host     string
	Port     uint16
}

func (r *Request) Addr() string {
	return net.JoinHostPort(
		r.Host,
		strconv.Itoa(int(r.Port)),
	)
}

func ReadRequest(reader io.Reader) (*Request, error) {
	var header [4]byte

	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, fmt.Errorf("read request header: %w", err)
	}

	if header[0] != socksVersion {
		return nil, fmt.Errorf(
			"invalid SOCKS version: %d",
			header[0],
		)
	}

	req := &Request{
		Cmd:      header[1],
		AddrType: header[3],
	}

	switch req.AddrType {

	case addrIPv4:
		var ip [4]byte

		if _, err := io.ReadFull(reader, ip[:]); err != nil {
			return nil, fmt.Errorf(
				"read IPv4 address: %w",
				err,
			)
		}

		req.Host = net.IP(ip[:]).String()

	case addrDomain:
		var length [1]byte

		if _, err := io.ReadFull(reader, length[:]); err != nil {
			return nil, fmt.Errorf(
				"read domain length: %w",
				err,
			)
		}

		domain := make([]byte, int(length[0]))

		if _, err := io.ReadFull(reader, domain); err != nil {
			return nil, fmt.Errorf(
				"read domain: %w",
				err,
			)
		}

		req.Host = string(domain)

	case addrIPv6:
		var ip [16]byte

		if _, err := io.ReadFull(reader, ip[:]); err != nil {
			return nil, fmt.Errorf(
				"read IPv6 address: %w",
				err,
			)
		}

		req.Host = net.IP(ip[:]).String()

	default:
		return nil, fmt.Errorf(
			"unsupported address type: %d",
			req.AddrType,
		)
	}

	var port [2]byte

	if _, err := io.ReadFull(reader, port[:]); err != nil {
		return nil, fmt.Errorf(
			"read port: %w",
			err,
		)
	}

	req.Port = uint16(port[0])<<8 | uint16(port[1])

	return req, nil
}

func (r *Request) writeReply(w io.Writer, status byte) error {
	reply := []byte{
		socksVersion,
		status,
		0x00,
		addrIPv4,
		// BND.ADDR = 0.0.0.0
		0x00, 0x00, 0x00, 0x00,
		// BND.PORT = 0
		0x00, 0x00,
	}
	_, err := w.Write(reply)
	return err
}

func (r *Request) proxy(client net.Conn) error {
	if r.Cmd != cmdConnect {
		return r.writeReply(client, 7)
	}
	target, err := net.DialTimeout(
		"tcp",
		r.Addr(),
		10*time.Second,
	)
	if err != nil {
		log.Printf(
			"failed to connect to %s: %v",
			r.Addr(),
			err,
		)

		return r.writeReply(client, 5)
	}

	defer target.Close()
	// Connection established
	if err := r.writeReply(client, 0); err != nil {
		return fmt.Errorf(
			"write success reply: %w",
			err,
		)
	}

	// Client -> Target
	go func() {
		_, _ = io.Copy(target, client)
		if tcp, ok := target.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}()
	// Target -> Client
	_, err = io.Copy(client, target)
	return err
}
