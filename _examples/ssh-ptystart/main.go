package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"

	"github.com/charmbracelet/ssh"
)

func main() {
	ssh.Handle(func(s ssh.Session) {
		log.Printf("connected %s %s %q", s.User(), s.RemoteAddr(), s.RawCommand())
		defer log.Printf("disconnected %s %s", s.User(), s.RemoteAddr())

		pty, _, ok := s.Pty()
		if !ok {
			io.WriteString(s, "No PTY requested.\n")
			s.Exit(1)
			return
		}

		cmd := exec.Command("powershell.exe")
		cmd.Env = append(os.Environ(), "SSH_TTY=windows-pty", fmt.Sprintf("TERM=%s", pty.Term))
		if err := pty.Start(cmd); err != nil {
			fmt.Fprintln(s, err.Error())
			s.Exit(1)
			return
		}

		// ProcessState gets populated by pty.Start
		for {
			if cmd.ProcessState != nil {
				break
			}
		}

		s.Exit(cmd.ProcessState.ExitCode())
	})

	log.Println("starting ssh server on port 2222...")
	if err := ssh.ListenAndServe(":2222", nil, ssh.AllocatePty()); err != nil && err != ssh.ErrServerClosed {
		log.Fatal(err)
	}
}
