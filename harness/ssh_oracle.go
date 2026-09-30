// solidSNAKE - dev-time oracle: a minimal SSH-2 password-auth server, used to verify the solidSNAKE
// sshspray client (both the success and the credential-failure path) against
// golang.org/x/crypto/ssh - the exact stack Ranger C3 authenticates through.
//
// Usage: sshoracle [user] [password]      (defaults: sshtest / sshtestpw)
// Listens on 0.0.0.0:22. Session channels are accepted and any "exec" request is answered
// with success + exit-status 0 (the command itself is not run); when SSHORACLE_LOG is set each
// exec command line is appended there, which lets the autodeploy diff prove both clients send
// the identical C3 install command. Run it inside a throwaway network namespace so it never
// touches the host SSH service (see the ad-hoc runner: unshare -n, then `ip link set lo up`).
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
)

func main() {
	user, pass := "sshtest", "sshtestpw"
	if len(os.Args) > 1 {
		user = os.Args[1]
	}
	if len(os.Args) > 2 {
		pass = os.Args[2]
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		log.Fatalf("signer: %v", err)
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if c.User() == user && string(pw) == pass {
				return nil, nil
			}
			return nil, fmt.Errorf("password rejected")
		},
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "0.0.0.0:22")
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	fmt.Printf("sshoracle: listening on :22 (accepts %s/%s)\n", user, pass)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			_, chans, reqs, err := ssh.NewServerConn(c, cfg)
			if err != nil {
				return // rejected credential or protocol error - nothing to serve
			}
			go ssh.DiscardRequests(reqs)
			for newCh := range chans {
				ch, chReqs, err := newCh.Accept()
				if err != nil {
					continue
				}
				go func(ch ssh.Channel, reqs <-chan *ssh.Request) {
					defer ch.Close()
					for req := range reqs {
						if req.Type == "exec" {
							var payload struct{ Command string }
							ssh.Unmarshal(req.Payload, &payload)
							if lg := os.Getenv("SSHORACLE_LOG"); lg != "" {
								if f, ferr := os.OpenFile(lg, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); ferr == nil {
									f.WriteString(payload.Command + "\n")
									f.Close()
								}
							}
							req.Reply(true, nil)
							ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
							return
						}
						req.Reply(false, nil)
					}
				}(ch, chReqs)
			}
		}(conn)
	}
}
