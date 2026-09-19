// Development-only loopback SSH server used to exercise the plugin's SSH and
// SFTP code paths without touching system SSH settings. Password: any non-empty
// value. Supports exec, PTY interactive shell and the sftp subsystem.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"

	"github.com/creack/pty"
	"github.com/pkg/sftp"
	gossh "golang.org/x/crypto/ssh"
)

type channelState struct {
	channel      gossh.Channel
	ptyRequested bool
	ptmx         *os.File
	cmd          *exec.Cmd
}

func main() {
	address := "127.0.0.1:2222"
	if len(os.Args) > 1 {
		address = os.Args[1]
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	signer, err := gossh.NewSignerFromKey(privateKey)
	if err != nil {
		log.Fatal(err)
	}
	config := &gossh.ServerConfig{
		PasswordCallback: func(conn gossh.ConnMetadata, password []byte) (*gossh.Permissions, error) {
			log.Printf("login: user=%s password.len=%d", conn.User(), len(password))
			return &gossh.Permissions{}, nil
		},
	}
	config.AddHostKey(signer)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("test ssh server listening on %s (any username/password)", address)
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go handleConn(conn, config)
	}
}

func handleConn(conn net.Conn, config *gossh.ServerConfig) {
	serverConn, channels, requests, err := gossh.NewServerConn(conn, config)
	if err != nil {
		log.Printf("handshake failed: %v", err)
		return
	}
	log.Printf("connected: %s", serverConn.RemoteAddr())
	go gossh.DiscardRequests(requests)
	for newChannel := range channels {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(gossh.UnknownChannelType, "unsupported")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			continue
		}
		go handleSession(&channelState{channel: channel}, requests)
	}
}

func handleSession(state *channelState, requests <-chan *gossh.Request) {
	defer state.channel.Close()
	// Requests are dispatched concurrently so window-change is applied while
	// the interactive shell or the sftp subsystem is running.
	execCh := make(chan string, 1)
	shellCh := make(chan bool, 1)
	sftpCh := make(chan bool, 1)
	go func() {
		defer close(execCh)
		defer close(shellCh)
		defer close(sftpCh)
		for request := range requests {
			switch request.Type {
			case "pty-req":
				state.ptyRequested = true
				if request.WantReply {
					_ = request.Reply(true, nil)
				}
			case "shell":
				if request.WantReply {
					_ = request.Reply(true, nil)
				}
				select {
				case shellCh <- true:
				default:
				}
			case "exec":
				command := string(request.Payload[4:])
				log.Printf("exec: %q", command)
				if request.WantReply {
					_ = request.Reply(true, nil)
				}
				select {
				case execCh <- command:
				default:
				}
			case "subsystem":
				name := string(request.Payload[4:])
				accepted := name == "sftp"
				if request.WantReply {
					_ = request.Reply(accepted, nil)
				}
				if accepted {
					select {
					case sftpCh <- true:
					default:
					}
				}
			case "window-change":
				if len(request.Payload) >= 8 && state.ptmx != nil {
					cols := binary.BigEndian.Uint32(request.Payload[0:4])
					rows := binary.BigEndian.Uint32(request.Payload[4:8])
					_ = pty.Setsize(state.ptmx, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
				}
				if request.WantReply {
					_ = request.Reply(true, nil)
				}
			case "env":
				if request.WantReply {
					_ = request.Reply(true, nil)
				}
			default:
				if request.WantReply {
					_ = request.Reply(false, nil)
				}
			}
		}
	}()
	select {
	case command := <-execCh:
		runCommand(state.channel, command)
	case <-shellCh:
		runInteractiveShell(state)
	case <-sftpCh:
		server, err := sftp.NewServer(state.channel)
		if err != nil {
			log.Printf("sftp setup failed: %v", err)
			return
		}
		log.Printf("sftp subsystem started")
		if err := server.Serve(); err != nil && err != io.EOF {
			log.Printf("sftp serve ended: %v", err)
		}
		_ = server.Close()
	}
}

func runInteractiveShell(state *channelState) {
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/zsh"
	}
	cmd := exec.Command(shell, "-i")
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")
	ptmx, err := pty.Start(cmd)
	if err != nil {
		log.Printf("pty start failed: %v", err)
		return
	}
	state.ptmx = ptmx
	log.Printf("interactive shell started (%s)", shell)

	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(state.channel, ptmx)
		close(done)
	}()
	go func() {
		_, _ = io.Copy(ptmx, state.channel)
	}()
	<-done
	_ = ptmx.Close()
	_ = cmd.Wait()
	writeExitStatus(state.channel, 0)
	log.Printf("interactive shell exited")
}

func runCommand(channel gossh.Channel, command string) {
	cmd := exec.Command("/bin/sh", "-c", command)
	cmd.Stdout = channel
	cmd.Stderr = channel.Stderr()
	stdin, err := cmd.StdinPipe()
	if err == nil {
		_ = stdin.Close()
	}
	if err := cmd.Start(); err != nil {
		writeExitStatus(channel, 127)
		return
	}
	err = cmd.Wait()
	status := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			status = exitErr.ExitCode()
			if status < 0 {
				status = 255
			}
		} else {
			status = 127
		}
	}
	writeExitStatus(channel, uint32(status))
}

func writeExitStatus(channel gossh.Channel, status uint32) {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, status)
	_, _ = channel.SendRequest("exit-status", false, payload)
}

var _ = fmt.Sprintf
