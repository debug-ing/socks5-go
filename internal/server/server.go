package server

import (
	"fmt"
	"log"
	"net"
	"socks5/internal/auth"
	"socks5/internal/protocol"
)

type Server struct {
	auth.Auth
	Port int
	Type string
}

func (s *Server) Run() {
	pro := protocol.NewProtocol(s.Type, s.Auth)
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", s.Port))
	if err != nil {
		panic(fmt.Sprintf("Failed to bind to port %d: %v", s.Port, err))
	}
	defer listener.Close()
	log.Printf("Server listening on port %d", s.Port)
	for {
		conn, err := listener.Accept()
		if err != nil {
			// return
			continue
		}
		go pro.HandleConnection(conn)
	}
}
