package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/charmbracelet/ssh"
)

func main() {
	ssh.Handle(func(s ssh.Session) {
		log.Printf("connected %s %s %q", s.User(), s.RemoteAddr(), s.RawCommand())
		defer log.Printf("disconnected %s %s", s.User(), s.RemoteAddr())

		pty, _, ok := s.Pty()
		if !ok {
			_, _ = fmt.Fprintln(s, "No PTY requested.")
			_ = s.Exit(1)
			return
		}

		name := "bash"
		if runtime.GOOS == "windows" {
			name = "powershell.exe"
		}
		cmd := exec.Command(name)
		cmd.Env = append(os.Environ(), "SSH_TTY="+pty.Name(), fmt.Sprintf("TERM=%s", pty.Term))
		if err := pty.Start(cmd); err != nil {
			_, _ = fmt.Fprintln(s, err.Error())
			_ = s.Exit(1)
			return
		}

		if runtime.GOOS == "windows" {
			// ProcessState gets populated by pty.Start waiting on the process
			// to exit.
			for cmd.ProcessState == nil {
				time.Sleep(100 * time.Millisecond)
			}

			_ = s.Exit(cmd.ProcessState.ExitCode())
			return
		}

		if err := cmd.Wait(); err != nil {
			_, _ = fmt.Fprintln(s, err)
			_ = s.Exit(cmd.ProcessState.ExitCode())
		}
	})

	log.Println("starting ssh server on port 2222...")
	if err := ssh.ListenAndServe("127.0.0.1:2222", nil, ssh.AllocatePty()); err != nil && err != ssh.ErrServerClosed {
		log.Fatal(err)
	}
}
