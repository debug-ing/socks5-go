package protocol

import (
	"net"
	"socks5/internal/auth"
	"time"

	ss "socks5/internal/protocol/socks4"
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
	} else if t == "socks4" {
		return &ss.Socks4{
			Dialer: net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			},
		}
	}
	panic("Not Support!")
}
