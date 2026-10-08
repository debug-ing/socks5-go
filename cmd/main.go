package main

import (
	"socks5/internal/auth"
	"socks5/internal/server"
)

func main() {
	server := &server.Server{
		Port: 1080,
		Type: "socks5",
		Auth: auth.Auth{
			AllowNoAuth:       true,
			AllowPasswordAuth: true,
			Users: map[string]string{
				"admin": "123456",
			},
		},
	}
	server.Run()
}
