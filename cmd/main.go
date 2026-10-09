package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"socks5/config"
	"socks5/internal/auth"
	"socks5/internal/server"
)

func main() {
	configPath := flag.String(
		"c",
		"config.yaml",
		"Path to configuration file",
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "Options:")
		flag.PrintDefaults()
	}

	flag.Parse()

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	for _, s := range cfg.Servers {
		users := make(map[string]string, len(s.Auth.Users))
		for _, u := range s.Auth.Users {
			users[u.Username] = u.Password
		}

		srv := &server.Server{
			Port: s.Port,
			Type: s.Type,
			Auth: auth.Auth{
				AllowNoAuth:       !s.Auth.Status,
				AllowPasswordAuth: s.Auth.Status,
				Users:             users,
			},
		}

		log.Printf("Starting %s on port %d", s.Name, s.Port)

		go srv.Run()
	}

	select {}
}
