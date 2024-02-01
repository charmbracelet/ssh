//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris
// +build darwin dragonfly freebsd linux netbsd openbsd solaris

package ssh

import (
	"os"
	"os/exec"

	"github.com/charmbracelet/x/exp/term/termios"
	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

type impl struct {
	// Master is the master PTY file descriptor.
	Master *os.File

	// Slave is the slave PTY file descriptor.
	Slave *os.File
}

func (i *impl) IsZero() bool {
	return i.Master == nil && i.Slave == nil
}

// Name returns the name of the slave PTY.
func (i *impl) Name() string {
	return i.Slave.Name()
}

// Read implements ptyInterface.
func (i *impl) Read(p []byte) (n int, err error) {
	return i.Master.Read(p)
}

// Write implements ptyInterface.
func (i *impl) Write(p []byte) (n int, err error) {
	return i.Master.Write(p)
}

func (i *impl) Close() error {
	if err := i.Master.Close(); err != nil {
		return err
	}
	return i.Slave.Close()
}

func (i *impl) Resize(w int, h int) (rErr error) {
	conn, err := i.Master.SyscallConn()
	if err != nil {
		return err
	}

	return conn.Control(func(fd uintptr) {
		rErr = termios.SetWinSize(fd, &unix.Winsize{
			Row: uint16(h),
			Col: uint16(w),
		})
	})
}

func (i *impl) start(c *exec.Cmd) error {
	c.Stdin, c.Stdout, c.Stderr = i.Slave, i.Slave, i.Slave
	return c.Start()
}

func newPty(_ Context, _ string, win Window, modes ssh.TerminalModes) (_ impl, rErr error) {
	ptm, pts, err := pty.Open()
	if err != nil {
		return impl{}, err
	}

	conn, err := ptm.SyscallConn()
	if err != nil {
		return impl{}, err
	}

	if err := conn.Control(func(fd uintptr) {
		rErr = applyTerminalModesToFd(fd, win.Width, win.Height, modes)
	}); err != nil {
		return impl{}, err
	}

	return impl{Master: ptm, Slave: pts}, rErr
}

func applyTerminalModesToFd(fd uintptr, width int, height int, modes ssh.TerminalModes) error {
	var ispeed, ospeed uint32
	ccs := map[string]uint8{}
	bools := map[string]bool{}
	for op, value := range modes {
		switch op {
		case ssh.TTY_OP_ISPEED:
			ispeed = value
		case ssh.TTY_OP_OSPEED:
			ospeed = value
		default:
			name, ok := sshToCc[op]
			if ok {
				ccs[name] = uint8(value)
				continue
			}
			name, ok = sshToBools[op]
			if ok {
				bools[name] = value > 0
				continue
			}

		}
	}
	if err := termios.SetTermios(int(fd), ispeed, ospeed, ccs, bools); err != nil {
		return err
	}
	return termios.SetWinSize(fd, &unix.Winsize{
		Row: uint16(height),
		Col: uint16(width),
	})
}

var sshToCc = map[uint8]string{
	ssh.VINTR:    "intr",
	ssh.VQUIT:    "quit",
	ssh.VERASE:   "erase",
	ssh.VKILL:    "kill",
	ssh.VEOF:     "eof",
	ssh.VEOL:     "eol",
	ssh.VEOL2:    "eol2",
	ssh.VSTART:   "start",
	ssh.VSTOP:    "stop",
	ssh.VSUSP:    "susp",
	ssh.VWERASE:  "werase",
	ssh.VREPRINT: "rprnt",
	ssh.VLNEXT:   "lnext",
	ssh.VDISCARD: "discard",
	ssh.VSTATUS:  "status",
	ssh.VSWTCH:   "swtch",
	ssh.VFLUSH:   "flush",
	ssh.VDSUSP:   "dsusp",
}

var sshToBools = map[uint8]string{
	ssh.IGNPAR:  "ignpar",
	ssh.PARMRK:  "parmrk",
	ssh.INPCK:   "inpck",
	ssh.ISTRIP:  "istrip",
	ssh.INLCR:   "inlcr",
	ssh.IGNCR:   "igncr",
	ssh.ICRNL:   "icrnl",
	ssh.IUCLC:   "iuclc",
	ssh.IXON:    "ixon",
	ssh.IXANY:   "ixany",
	ssh.IXOFF:   "ixoff",
	ssh.IMAXBEL: "imaxbel",

	ssh.IUTF8:   "iutf8",
	ssh.ISIG:    "isig",
	ssh.ICANON:  "icanon",
	ssh.ECHO:    "echo",
	ssh.ECHOE:   "echoe",
	ssh.ECHOK:   "echok",
	ssh.ECHONL:  "echonl",
	ssh.NOFLSH:  "noflsh",
	ssh.TOSTOP:  "tostop",
	ssh.IEXTEN:  "iexten",
	ssh.ECHOCTL: "echoctl",
	ssh.ECHOKE:  "echoke",
	ssh.PENDIN:  "pendin",
	ssh.XCASE:   "xcase",

	ssh.OPOST:  "opost",
	ssh.OLCUC:  "olcuc",
	ssh.ONLCR:  "onlcr",
	ssh.OCRNL:  "ocrnl",
	ssh.ONOCR:  "onocr",
	ssh.ONLRET: "onlret",

	ssh.CS7:    "cs7",
	ssh.CS8:    "cs8",
	ssh.PARENB: "parenb",
	ssh.PARODD: "parodd",
}
