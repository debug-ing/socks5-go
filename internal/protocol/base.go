package protocol

import (
	"net"
	"socks5/internal/auth"

	s "socks5/internal/protocol/socks5"
)

type Base interface {
	HandleConnection(conn net.Conn)
}

func NewProtocol(t string, auth auth.Auth) Base {
	if t == "socks5" {
		return &s.Socks5{
			Auth: auth,
		}
	}
	panic("Not Support!")
}
