package main

import (
	"fmt"
	"net"
	"socks5/internal/auth"
	"socks5/internal/server"
	"time"
)

func main() {
	srv := &server.Server{
		Port: 1080,
		Type: "socks5",
		Auth: auth.Auth{
			AllowNoAuth:       true,
			AllowPasswordAuth: false,
			Users:             map[string]string{},
		},
	}

	go srv.Run()
	time.Sleep(2 * time.Second)
	if s := check("127.0.0.1", 1080); !s {
		panic("Test Socks5 No Auth failed")
	}
}

func check(ip string, port int) bool {
	address := fmt.Sprintf("%s:%d", ip, port)

	conn, err := net.DialTimeout("tcp", address, 1*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()

	_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	if err != nil {
		return false
	}

	resp := make([]byte, 2)
	_, err = conn.Read(resp)
	if err != nil {
		return false
	}

	if resp[0] == 0x05 && resp[1] == 0x00 {
		return true
	}

	return false
}
