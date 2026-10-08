package internal

import (
	"log"
	"net"
	"socks5/internal/auth"
)

type Socks5 struct {
	Auth auth.Auth
}

func (s *Socks5) HandleConnection(conn net.Conn) {
	defer conn.Close()
	user, err := s.Auth.Authenticate(conn)
	if err != nil {
		log.Printf("authentication failed: %v", err)
		return
	}

	if user != "" {
		log.Printf("authenticated user: %s", user)
	} else {
		log.Printf("anonymous connection")
	}

	req, err := ReadRequest(conn)
	if err != nil {
		log.Printf("read request: %v", err)
		return
	}
	log.Printf(
		"user=%q connect=%s",
		user,
		req.Addr(),
	)
	if err := req.proxy(conn); err != nil {
		log.Printf("proxy: %v", err)
	}
}
