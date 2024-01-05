//go:build !linux && !darwin && !freebsd && !dragonfly && !netbsd && !openbsd && !solaris
// +build !linux,!darwin,!freebsd,!dragonfly,!netbsd,!openbsd,!solaris

// TODO: support Windows
package ssh

import (
	"golang.org/x/crypto/ssh"
)

type impl struct{}

func (i *impl) Read(p []byte) (n int, err error) {
	return 0, ErrUnsupported
}

func (i *impl) Write(p []byte) (n int, err error) {
	return 0, ErrUnsupported
}

func (i *impl) Resize(w int, h int) error {
	return ErrUnsupported
}

func (i *impl) Close() error {
	return nil
}

func newPty(Context, string, Window, ssh.TerminalModes) (impl, error) {
	return impl{}, ErrUnsupported
}
