package native

import (
	"fastdbg2/native/internal/arch"
	"fastdbg2/native/internal/launch"
	"os"
	"os/exec"
	"path/filepath"
)

type launchGate struct {
	process   *os.Process
	pidfd     int
	profile   *arch.Descriptor
	exeInfo   os.FileInfo
	bootstrap *launch.Process
}

func startLaunch(path string, args []string) (*launchGate, error) {
	resolved, err := exec.LookPath(path)
	if err != nil {
		return nil, err
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(resolved)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	profile, err := profileForELF(f)
	if err != nil {
		return nil, err
	}
	exeInfo, err := f.Stat()
	if err != nil {
		return nil, err
	}
	argv := append([]string{resolved}, args...)
	bootstrap, err := launch.Start(f, argv, [3]*os.File{os.Stdin, os.Stdout, os.Stderr})
	if err != nil {
		return nil, err
	}
	return &launchGate{
		process:   bootstrap.Process,
		pidfd:     bootstrap.PIDFD,
		profile:   profile,
		exeInfo:   exeInfo,
		bootstrap: bootstrap,
	}, nil
}

func (g *launchGate) release() error { return g.bootstrap.Release() }

func (g *launchGate) execError() error { return g.bootstrap.ExecError() }

func (g *launchGate) close() error { return g.bootstrap.Close() }
