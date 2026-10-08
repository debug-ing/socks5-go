package auth

import (
	"fmt"
	"io"
	"net"
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

type Auth struct {
	AllowNoAuth       bool
	AllowPasswordAuth bool
	Users             map[string]string
}

func (s *Auth) Authenticate(conn net.Conn) (string, error) {
	var header [2]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return "", fmt.Errorf("read auth header: %w", err)
	}
	if header[0] != socksVersion {
		return "", fmt.Errorf("invalid SOCKS version: %d", header[0])
	}
	nMethods := int(header[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", fmt.Errorf("read auth methods: %w", err)
	}
	if s.AllowPasswordAuth {
		for _, method := range methods {
			if method == authUsernamePasswd {
				if _, err := conn.Write([]byte{
					socksVersion,
					authUsernamePasswd,
				}); err != nil {
					return "", err
				}

				return s.authenticateUserPassword(conn)
			}
		}
	}

	if s.AllowNoAuth {
		for _, method := range methods {
			if method == authNone {
				if _, err := conn.Write([]byte{
					socksVersion,
					authNone,
				}); err != nil {
					return "", err
				}

				return "", nil
			}
		}
	}

	_, _ = conn.Write([]byte{
		socksVersion,
		authNoAccept,
	})

	return "", fmt.Errorf("no acceptable authentication method")
}

func (s *Auth) authenticateUserPassword(conn net.Conn) (string, error) {
	var header [2]byte

	// VER + ULEN
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return "", fmt.Errorf("read username header: %w", err)
	}

	if header[0] != 1 {
		return "", fmt.Errorf("invalid username/password version: %d", header[0])
	}

	usernameLen := int(header[1])

	username := make([]byte, usernameLen)

	if _, err := io.ReadFull(conn, username); err != nil {
		return "", fmt.Errorf("read username: %w", err)
	}

	var passwordLen [1]byte

	if _, err := io.ReadFull(conn, passwordLen[:]); err != nil {
		return "", fmt.Errorf("read password length: %w", err)
	}

	password := make([]byte, int(passwordLen[0]))

	if _, err := io.ReadFull(conn, password); err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}

	user := string(username)
	pass := string(password)

	expected, ok := s.Users[user]

	if !ok || expected != pass {
		_, _ = conn.Write([]byte{1, 1})

		return "", fmt.Errorf("invalid username/password")
	}

	if _, err := conn.Write([]byte{1, 0}); err != nil {
		return "", err
	}

	return user, nil
}
