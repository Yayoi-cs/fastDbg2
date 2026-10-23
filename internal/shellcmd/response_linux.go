package shellcmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

const responseLimit = 32 << 10

type supervisorResponse struct {
	value result
	err   error
}

func readSupervisorResponse(file *os.File, supervisor int) supervisorResponse {
	defer file.Close()
	connection, err := file.SyscallConn()
	if err != nil {
		return supervisorResponse{err: err}
	}
	var data []byte
	var readErr error
	err = connection.Control(func(fd uintptr) {
		if err := unix.SetNonblock(int(fd), true); err != nil {
			readErr = err
			return
		}
		var buffer [4096]byte
		exited := false
		for {
			n, err := unix.Read(int(fd), buffer[:min(len(buffer), responseLimit+1-len(data))])
			if n > 0 {
				data = append(data, buffer[:n]...)
				if len(data) > responseLimit {
					readErr = errors.New("shell supervisor response exceeds 32768 bytes")
					return
				}
			}
			if err == nil {
				if n == 0 {
					return
				}
				continue
			}
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if !errors.Is(err, unix.EAGAIN) {
				readErr = err
				return
			}
			if exited {
				readErr = errors.New("shell supervisor response pipe remained open after supervisor exit")
				return
			}
			fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}, {Fd: int32(supervisor), Events: unix.POLLIN}}
			for {
				_, err = unix.Poll(fds, -1)
				if !errors.Is(err, unix.EINTR) {
					break
				}
			}
			if err != nil {
				readErr = err
				return
			}
			if fds[0].Revents&unix.POLLNVAL != 0 || fds[1].Revents&unix.POLLNVAL != 0 {
				readErr = errors.New("shell supervisor response descriptor is invalid")
				return
			}
			exited = fds[1].Revents&(unix.POLLIN|unix.POLLHUP|unix.POLLERR) != 0
		}
	})
	if err := errors.Join(err, readErr); err != nil {
		return supervisorResponse{err: err}
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 || data[0] != '{' {
		return supervisorResponse{err: errors.New("shell supervisor response must be a JSON object")}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var response result
	if err := decoder.Decode(&response); err != nil {
		return supervisorResponse{err: err}
	}
	if response.Code < 0 || response.Code > 255 || response.Signal < 0 || response.Signal > 64 || response.Code != 0 && response.Signal != 0 || len(response.Error) > 4096 {
		return supervisorResponse{err: errors.New("invalid shell supervisor exit status or error length")}
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return supervisorResponse{err: errors.New("unexpected trailing shell supervisor response")}
	}
	return supervisorResponse{value: response}
}
