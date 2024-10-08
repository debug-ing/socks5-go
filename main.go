package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"runtime"
	"sync"
	"time"
)

const (
	socksVersion       = 5
	authNone           = 0
	authUsernamePasswd = 2
	authNoAccept       = 0xFF
	cmdConnect         = 1
	addrIPv4           = 1
	addrDomain         = 3
	addrIPv6           = 4
)

var (
	Users               = map[string]string{}
	TrafficUsage        = map[string]int64{}
	trafficMutex        = sync.Mutex{}
	trafficSaverRWMutex = sync.RWMutex{}
	usersFile           = "users.json"
	trafficFile         = "traffic.json"
)

type countingConn struct {
	conn   net.Conn
	user   string
	rBytes int64
	wBytes int64
}

func (c *countingConn) Read(b []byte) (int, error) {
	n, err := c.conn.Read(b)
	trafficMutex.Lock()
	c.rBytes += int64(n)
	TrafficUsage[c.user] += int64(n)
	trafficMutex.Unlock()
	return n, err
}

func (c *countingConn) Write(b []byte) (int, error) {
	n, err := c.conn.Write(b)
	trafficMutex.Lock()
	c.wBytes += int64(n)
	TrafficUsage[c.user] += int64(n)
	trafficMutex.Unlock()
	return n, err
}

func (c *countingConn) Close() error {
	return c.conn.Close()
}

func loadUsers() {
	file, err := ioutil.ReadFile(usersFile)
	if err != nil {
		if os.IsNotExist(err) {
			log.Println("No users file found, starting with an empty user list")
			return
		}
		log.Fatalf("Failed to read users file: %v", err)
	}

	if err := json.Unmarshal(file, &Users); err != nil {
		log.Fatalf("Failed to unmarshal users: %v", err)
	}
}

func saveUsers() {
	file, err := json.MarshalIndent(Users, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal users: %v", err)
	}

	if err := ioutil.WriteFile(usersFile, file, 0600); err != nil {
		log.Fatalf("Failed to write users file: %v", err)
	}
}

func loadTraffic() {
	trafficSaverRWMutex.RLock()
	defer trafficSaverRWMutex.RUnlock()
	file, err := ioutil.ReadFile(trafficFile)
	if err != nil {
		if os.IsNotExist(err) {
			log.Println("No traffic file found, starting with an empty traffic record")
			return
		}
		log.Fatalf("Failed to read traffic file: %v", err)
	}

	if err := json.Unmarshal(file, &TrafficUsage); err != nil {
		log.Fatalf("Failed to unmarshal traffic: %v", err)
	}
}

func saveTraffic() {
	trafficSaverRWMutex.Lock()
	defer trafficSaverRWMutex.Unlock()
	file, err := json.MarshalIndent(TrafficUsage, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal traffic: %v", err)
	}
	if err := ioutil.WriteFile(trafficFile, file, 0600); err != nil {
		log.Fatalf("Failed to write traffic file: %v", err)
	}
}

func addUser(username, password string) {
	Users[username] = password
	saveUsers()
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	// buf := make([]byte, 32768)
	buf := make([]byte, 1024*1024)
	// buf := []byte
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		log.Println("Failed to read version and nMethods:", err)
		return
	}

	nMethods := int(buf[1])
	if _, err := io.ReadFull(conn, buf[:nMethods]); err != nil {
		log.Println("Failed to read methods:", err)
		return
	}

	supported := false
	for _, method := range buf[:nMethods] {
		if method == authUsernamePasswd {
			supported = true
			break
		}
	}

	if !supported {
		conn.Write([]byte{socksVersion, authNoAccept})
		return
	}

	conn.Write([]byte{socksVersion, authUsernamePasswd})

	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		log.Println("Failed to read auth version and username length:", err)
		return
	}

	usernameLen := int(buf[1])
	if _, err := io.ReadFull(conn, buf[:usernameLen]); err != nil {
		log.Println("Failed to read username:", err)
		return
	}
	username := string(buf[:usernameLen])

	if _, err := io.ReadFull(conn, buf[:1]); err != nil {
		log.Println("Failed to read password length:", err)
		return
	}

	passwordLen := int(buf[0])
	if _, err := io.ReadFull(conn, buf[:passwordLen]); err != nil {
		log.Println("Failed to read password:", err)
		return
	}
	password := string(buf[:passwordLen])

	if userPassword, ok := Users[username]; !ok || userPassword != password {
		conn.Write([]byte{1, 1}) // Authentication failed
		return
	}

	conn.Write([]byte{1, 0}) // Authentication successful

	countingConn := &countingConn{conn: conn, user: username}
	defer countingConn.Close()
	if _, err := io.ReadFull(countingConn, buf[:4]); err != nil {
		log.Println("Failed to read request header:", err)
		return
	}

	if buf[1] != cmdConnect {
		log.Println("Unsupported command:", buf[1])
		countingConn.Write([]byte{socksVersion, 7})
		return
	}

	var addr string
	switch buf[3] {
	case addrIPv4:
		if _, err := io.ReadFull(countingConn, buf[:4]); err != nil {
			log.Println("Failed to read IPv4 address:", err)
			return
		}
		addr = net.IP(buf[:4]).String()
		fmt.Printf("IPv4 address: %s\n", addr)
	case addrDomain:
		if _, err := io.ReadFull(countingConn, buf[:1]); err != nil {
			log.Println("Failed to read domain length:", err)
			return
		}
		domainLen := int(buf[0])
		if _, err := io.ReadFull(countingConn, buf[:domainLen]); err != nil {
			log.Println("Failed to read domain name:", err)
			return
		}
		addr = string(buf[:domainLen])
		fmt.Printf("Domain name: %s\n", addr)
	case addrIPv6:
		if _, err := io.ReadFull(countingConn, buf[:16]); err != nil {
			log.Println("Failed to read IPv6 address:", err)
			return
		}
		addr = net.IP(buf[:16]).String()
		fmt.Printf("IPv6 address: %s\n", addr)
	default:
		log.Println("Unsupported address type:", buf[3])
		countingConn.Write([]byte{socksVersion, 8})
		return
	}

	if _, err := io.ReadFull(countingConn, buf[:2]); err != nil {
		log.Println("Failed to read port:", err)
		return
	}
	port := int(buf[0])<<8 | int(buf[1])
	addr = net.JoinHostPort(addr, fmt.Sprintf("%d", port))

	targetConn, err := net.Dial("tcp", addr)

	if err != nil {
		log.Println("Failed to connect to target:", err)
		countingConn.Write([]byte{socksVersion, 5})
		return
	}
	defer targetConn.Close()

	countingConn.Write([]byte{socksVersion, 0, 0, addrIPv4, 0, 0, 0, 0, 0, 0})

	// ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	// defer cancel()

	// var once sync.Once
	closeConns := func() {
		// once.Do(func() {
		countingConn.Close()
		targetConn.Close()
		// })
	}

	// errCh := make(chan error, 1)
	go func() {
		// defer closeConns()
		defer closeConns()
		_, err := io.CopyBuffer(targetConn, countingConn, buf)
		if err != nil {
			log.Println("Error copying from countingConn to targetConn:", err)
		}

		// io.Copy(targetConn, countingConn)
		// io.wri
		// n, readErr := targetConn.Read(buf)
		// if n > 0 {
		// 	_, writeErr := countingConn.Write(buf[:n])
		// 	if writeErr != nil {
		// 		// Handling write error
		// 		fmt.Println("Error writing to targetConn:", writeErr)
		// 		return
		// 	}
		// }
		// if readErr != nil {
		// 	if readErr != io.EOF {
		// 		// Handling read error
		// 		fmt.Println("Error reading from countingConn:", readErr)
		// 	}
		// 	return
		// }
	}()

	func() {
		defer closeConns()
		_, err := io.CopyBuffer(countingConn, targetConn, buf)
		if err != nil {
			log.Println("Error copying from targetConn to countingConn:", err)
		}
		// _, _ = io.Copy(countingConn, targetConn)
		// n, readErr := targetConn.Read(buf)
		// if n > 0 {
		// 	_, writeErr := countingConn.Write(buf[:n])
		// 	if writeErr != nil {
		// 		// Handling write error
		// 		fmt.Println("Error writing to targetConn:", writeErr)
		// 		return
		// 	}
		// }
		// if readErr != nil {
		// 	if readErr != io.EOF {
		// 		// Handling read error
		// 		fmt.Println("Error reading from countingConn:", readErr)
		// 	}
		// 	return
		// }
		// errCh <- err
	}()
	// io.Copy(countingConn, targetConn)
	// select {
	// case <-ctx.Done():
	// 	log.Println("Connection timed out")
	// 	closeConns()
	// case err := <-errCh:
	// 	if err != nil && err != io.EOF {
	// 		log.Println("Connection error:", err)
	// 	}
	// 	closeConns()
	// }

	saveTraffic()
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "adduser":
			if len(os.Args) != 4 {
				fmt.Println("Usage: go run main.go adduser <username> <password> after build you can use ./main adduser <username> <password>")
				return
			}
			loadUsers()
			addUser(os.Args[2], os.Args[3])
			fmt.Println("User added successfully")
			return
		case "showtraffic":
			loadTraffic()
			for user, traffic := range TrafficUsage {
				fmt.Printf("User: %s, Traffic: %d bytes\n", user, traffic)
			}
			return
		}
	}

	loadUsers()
	loadTraffic()
	listener, err := net.Listen("tcp", ":1080")
	if err != nil {
		log.Fatalf("Failed to bind to port 1080: %v", err)
	}
	defer listener.Close()

	go func() {
		for {
			fmt.Printf("Active Goroutines: %d\n", runtime.NumGoroutine())
			time.Sleep(5 * time.Second)
		}
	}()

	log.Println("SOCKS5 server listening on port 1080")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Failed to accept connection:", err)
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				continue
			}
			log.Fatalf("Permanent error accepting connection: %v", err)
			return
		}

		go handleConnection(conn)
	}
}
