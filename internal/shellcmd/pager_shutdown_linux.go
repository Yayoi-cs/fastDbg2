package shellcmd

import (
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

const pagerExitGrace = time.Second

func stopPager(pid int, outcome *result) error {
	fd, err := childHandle(pid)
	if err != nil {
		return fmt.Errorf("cannot verify pager root before shutdown; terminal screen restoration is unconfirmed: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.PidfdSendSignal(fd, unix.SIGTERM, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
		return fmt.Errorf("cannot send SIGTERM to pager; terminal screen restoration is unconfirmed: %w", err)
	}
	deadline := time.Now().Add(pagerExitGrace)
	for {
		done, _, err := reap(pid, outcome)
		if err != nil {
			return fmt.Errorf("wait for pager shutdown; terminal screen restoration is unconfirmed: %w", err)
		}
		if done {
			if outcome.Signal != 0 {
				return pagerSignalError(outcome.Signal)
			}
			return nil
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return fmt.Errorf("pager did not exit within %s after SIGTERM; forcing owned cleanup; terminal screen restoration is unconfirmed", pagerExitGrace)
		}
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		_, err = unix.Poll(fds, int((remaining+time.Millisecond-1)/time.Millisecond))
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil || fds[0].Revents&unix.POLLNVAL != 0 {
			return fmt.Errorf("poll pager shutdown; terminal screen restoration is unconfirmed: %v", err)
		}
	}
}

func pagerSignalError(signal int) error {
	return fmt.Errorf("pager terminated by signal %d; terminal screen restoration is unconfirmed", signal)
}
