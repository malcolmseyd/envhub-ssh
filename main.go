package main

import (
	"bytes"
	"database/sql"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

var PORT = defaultEnv("PORT", "2222")
var KEYFILE = mustEnv("KEYFILE")

var privateKey ssh.Signer
var db *sql.DB

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
	}
	privateKey, err = ssh.ParsePrivateKey(privkeyBytes)
	if err != nil {
		log.Fatalln("failed to parse private key:", err)
	}
	db, err = sql.Open("sqlite3", "file:db.sqlite3")
	if err != nil {
		log.Fatalln("failed to open database:", err)
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
			return strings.TrimLeft(`
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

		err = handleChannel(conn, reqs, channel)
		if err != nil {
			log.Println(err)
		}
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
func handleChannel(conn *ssh.ServerConn, reqs <-chan *ssh.Request, channel ssh.Channel) error {
	defer channel.Close()
	defer channel.CloseWrite()
	for r := range reqs {
		switch r.Type {
		case "exec":
			if r.WantReply {
				r.Reply(true, nil)
			}
			len := binary.BigEndian.Uint32(r.Payload[:4])
			cmd := string(r.Payload[4 : 4+len])
			return handleCommand(conn, channel, cmd)
		case "shell":
			if r.WantReply {
				r.Reply(true, nil)
			}
			return handleCommand(conn, channel, "")
		default:
			log.Println("unknown request type:", r.Type, r.WantReply)
		}

	}
	return nil
}

const help = `
Usage: ssh <USERNAME>@<HOSTNAME> <COMMAND>

Commands:
- help: print this help message
- read/<ID>: read an env file
- ls: list the ids of every env file you've written
- write: write an env file. returns the ID
- write/public: write an env file that everyone can see
- config/<ID>/visible: get list of users who can see the env file
- config/<ID>/show/<USERNAME>: make env file visible to user
- config/<ID>/hide/<USERNAME>: make env file not visible to user
`

func handleCommand(conn *ssh.ServerConn, channel ssh.Channel, cmd string) error {
	path := strings.Split(cmd, "/")
	if len(path) > 0 {
		cmd = path[0]
	}
	switch cmd {
	case "":
		// make sure it can write properly, they expect a TTY
		term := terminal.NewTerminal(channel, "")
		io.WriteString(term, strings.TrimLeft(help, "\n"))
	case "help":
		io.WriteString(channel, strings.TrimLeft(help, "\n"))

	case "read":
		if len(path) < 2 {
			io.WriteString(channel, "Usage: read/<ID>\n")
			return nil
		}
		id := path[1]
		row := db.QueryRow(`
			SELECT
				content, author, public,
				visibleTo.envs_id NOT NULL
			FROM envs
			LEFT JOIN visibleTo
				ON visibleTo.envs_id = id
				AND visibleTo.gh_username = ?
			WHERE id = ?
		`, conn.User(), id)
		var content, author string
		var public bool
		var visible bool
		err := row.Scan(&content, &author, &public, &visible)
		if err == sql.ErrNoRows {
			io.WriteString(channel.Stderr(), "env file not found\n")
			return nil
		}
		if err != nil {
			return fmt.Errorf("error reading env file: %w", err)
		}
		if !public && author != conn.User() && !visible {
			io.WriteString(channel.Stderr(), "you do not have permission to read this env file\n")
			return nil
		}
		io.WriteString(channel, content+"\n")
	case "write":
		public := false
		if len(path) > 1 && path[1] == "public" {
			public = true
		}
		io.WriteString(channel, "Write an env file. Press Ctrl+D when done.\n")
		content, err := io.ReadAll(channel)
		if err != nil {
			return fmt.Errorf("error reading content: %w", err)
		}
		res, err := db.Exec(`INSERT INTO envs (content, author, public) VALUES (?, ?, ?)`, string(content), conn.User(), public)
		if err != nil {
			return fmt.Errorf("error writing env file: %w", err)
		}
		id, err := res.LastInsertId()
		if err != nil {
			return fmt.Errorf("error getting ID: %w", err)
		}
		io.WriteString(channel, fmt.Sprintf("\nsuccess! your id is %d\n", id))
	case "ls":
		rows, err := db.Query(`
			SELECT id FROM envs
			WHERE author = ?
			`, conn.User())
		if err != nil {
			return fmt.Errorf("error listing env files: %w", err)
		}
		for rows.Next() {
			var id int64
			rows.Scan(&id)
			io.WriteString(channel, fmt.Sprintf("%d\n", id))
		}
		rows.Close()
	case "config":
		if len(path) < 3 {
			io.WriteString(channel,
				`Usage:
- config/<ID>/visible
- config/<ID>/show/<USERNAME>
- config/<ID>/hide/<USERNAME>
`)
			return nil
		}
		id := path[1]
		action := path[2]
		switch action {
		case "visible":
			rows, err := db.Query(`
				SELECT gh_username FROM visibleTo
				WHERE envs_id = ?
			`, id)
			if err != nil {
				return fmt.Errorf("error listing visible users: %w", err)
			}
			for rows.Next() {
				var username string
				rows.Scan(&username)
				io.WriteString(channel, fmt.Sprintf("%s\n", username))
			}
			rows.Close()

		case "show":
			if len(path) < 4 {
				io.WriteString(channel, "Usage\n")
				return nil
			}
			username := path[3]
			_, err := db.Exec(`
				INSERT INTO visibleTo (envs_id, gh_username)
				VALUES (?, ?)
			`, id, username)
			if err != nil {
				return fmt.Errorf("error making env file visible: %w", err)
			}
			io.WriteString(channel, fmt.Sprintf("made env file visible to %v\n", username))
		case "hide":
			if len(path) < 4 {
				io.WriteString(channel, "Usage\n")
				return nil
			}
			username := path[3]
			_, err := db.Exec(`
				DELETE FROM visibleTo
				WHERE envs_id = ? AND gh_username = ?
			`, id, username)
			if err != nil {
				return fmt.Errorf("error making env file visible: %w", err)
			}
			io.WriteString(channel, fmt.Sprintf("hid env file from %v\n", username))
		}
	}

	channel.SendRequest("exit-status", false, ssh.Marshal(struct{ C uint32 }{C: 0}))
	return nil
}
