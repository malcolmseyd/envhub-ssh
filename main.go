package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

var PORT = defaultEnv("PORT", "2222")
var KEYFILE = mustEnv("KEYFILE")

var privateKey ssh.Signer

func defaultEnv(key, def string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return def
}

func mustEnv(key string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	log.Fatalf("Missing environment variable %s", key)
	return ""
}

func init() {
	var err error
	privkeyBytes, err := os.ReadFile(KEYFILE)
	if err != nil {
		log.Fatalln("failed to open private key file:", err)
		return
	}
	privateKey, err = ssh.ParsePrivateKey(privkeyBytes)
	if err != nil {
		log.Fatalln("failed to parse private key:", err)
		return
	}

}

func main() {
	log.Fatalln(run())
}

func run() error {
	listener, err := net.Listen("tcp", net.JoinHostPort("", PORT))
	if err != nil {
		return err
	}
	log.Println("Listening on", listener.Addr())
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println(err)
			continue
		}

		go handleConn(conn)
	}
}

func handleConn(c net.Conn) {
	defer c.Close()
	log.Println("New connection from", c.RemoteAddr())

	sshConfig := ssh.ServerConfig{
		BannerCallback: func(conn ssh.ConnMetadata) string {
			return strings.TrimLeft(
				`
  ______            _    _       _     
 |  ____|          | |  | |     | |    
 | |__   _ ____   _| |__| |_   _| |__  
 |  __| | '_ \ \ / /  __  | | | | '_ \ 
 | |____| | | \ V /| |  | | |_| | |_) |
 |______|_| |_|\_/ |_|  |_|\__,_|_.__/ 

 `, "\n")

		},
		PublicKeyCallback: func(conn ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			log.Println("Public key for", conn.User()+":", string(bytes.TrimSpace(ssh.MarshalAuthorizedKey(k))))
			authed, err := authenticateGithub(conn.User(), k)
			if err != nil {
				log.Println("error authenticating user", conn.User()+":", err)
				return nil, err
			}
			if !authed {
				log.Println("GitHub authentication failed for", conn.User())
				return nil, fmt.Errorf("authentication failed for %s at %v", conn.User(), conn.RemoteAddr())
			}
			log.Println("GitHub authentication succeeded for", conn.User())
			return &ssh.Permissions{}, nil
		},
	}

	sshConfig.AddHostKey(privateKey)

	conn, newChans, reqs, err := ssh.NewServerConn(c, &sshConfig)
	if err != nil {
		log.Println("failed to accept connection:", err)
		return
	}
	_ = reqs

	for newChan := range newChans {
		if newChan.ChannelType() != "session" {
			newChan.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		log.Println("new channel from", conn.User()+"@"+conn.RemoteAddr().String())

		channel, reqs, err := newChan.Accept()
		if err != nil {
			log.Println(err)
			return
		}
		_ = reqs

		handleChannel(conn, channel)
	}
}

func authenticateGithub(username string, key ssh.PublicKey) (bool, error) {
	location, err := url.JoinPath("https://github.com", username+".keys")
	if err != nil {
		return false, err
	}
	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(location)
	if err != nil {
		return false, err
	}
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // 1MB limit
	if err != nil {
		return false, err
	}
	formattedKey := bytes.TrimSpace(ssh.MarshalAuthorizedKey(key))
	for _, line := range bytes.Split(bytes.TrimSpace(bodyBytes), []byte("\n")) {
		if bytes.Equal(line, formattedKey) {
			return true, nil
		}
	}
	return false, nil
}

// TODO business logic
func handleChannel(conn *ssh.ServerConn, channel ssh.Channel) {
	defer channel.Close()
	io.WriteString(channel, "Hello world!\n")
	channel.SendRequest("exit-status", false, ssh.Marshal(struct{ C uint32 }{0}))
	channel.CloseWrite()
	channel.Close()
}
