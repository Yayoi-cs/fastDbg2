package qemu

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"

	"fastdbg2/target"
)

func ConnectUnix(path string, options ...Options) (*Session, error) {
	value, err := normalizeOptions(options)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialTimeout("unix", path, value.Timeout)
	if err != nil {
		return nil, err
	}
	return connect(conn, value)
}

func (s *Session) Threads() ([]uint64, error) {
	if err := s.begin(); err != nil {
		return nil, err
	}
	defer s.end()
	var ids []uint64
	seen := make(map[uint64]bool)
	command := "qfThreadInfo"
	for {
		reply, err := s.request(command)
		if err != nil {
			return nil, err
		}
		if string(reply) == "l" {
			break
		}
		if len(reply) < 2 || reply[0] != 'm' {
			return nil, s.protocolError("invalid thread enumeration")
		}
		for _, value := range strings.Split(string(reply[1:]), ",") {
			id, err := parseThread(value)
			if err != nil {
				return nil, err
			}
			if seen[id] || len(ids) >= 65536 {
				return nil, s.protocolError("duplicate or excessive thread enumeration")
			}
			seen[id] = true
			ids = append(ids, id)
		}
		command = "qsThreadInfo"
	}
	if len(ids) == 0 {
		return nil, target.ErrUnavailable
	}
	slices.Sort(ids)
	return ids, nil
}

func (s *Session) SelectThread(id uint64) error {
	if id == 0 {
		return target.ErrInvalidArgument
	}
	if err := s.begin(); err != nil {
		return err
	}
	defer s.end()
	if s.selected != nil && *s.selected == id && s.inspectionThread != nil && *s.inspectionThread == id {
		return nil
	}
	if err := s.expectOK(fmt.Sprintf("Hg%x", id)); err != nil {
		return err
	}
	s.selected = &id
	s.inspectionThread = &id
	return nil
}

func (s *Session) Monitor(command string) (string, error) {
	if strings.ContainsAny(command, "\x00\r\n") || command == "" {
		return "", target.ErrInvalidArgument
	}
	if err := s.begin(); err != nil {
		return "", err
	}
	defer s.end()
	packet := "qRcmd," + hex.EncodeToString([]byte(command))
	if len(packet) > s.packetSize {
		return "", target.ErrOverflow
	}
	if err := s.protocol.send(packet, s.noAck); err != nil {
		return "", err
	}
	var output []byte
	reply, err := s.protocol.reply(s.noAck, false, func(data []byte) error {
		if len(data) > s.outputLimit-len(output) {
			return target.ErrOverflow
		}
		output = append(output, data...)
		return nil
	})
	if err != nil {
		return "", err
	}
	if err := remoteError(packet, reply); err != nil {
		return "", err
	}
	if string(reply) != "OK" {
		return "", fmt.Errorf("monitor %q: %w", command, target.ErrUnsupported)
	}
	return string(output), nil
}

func (s *Session) ReadPhysicalMemory(addr target.Address, data []byte) (n int, err error) {
	if !validRange(addr, len(data)) {
		return 0, target.ErrOverflow
	}
	if err := s.begin(); err != nil {
		return 0, err
	}
	defer s.end()
	mode, err := s.request("qqemu.PhyMemMode")
	if err != nil {
		return 0, err
	}
	if string(mode) != "0" && string(mode) != "1" {
		return 0, fmt.Errorf("QEMU physical memory mode: %w", target.ErrUnsupported)
	}
	if string(mode) == "0" {
		if err := s.expectOK("Qqemu.PhyMemMode:1"); err != nil {
			return 0, err
		}
		defer func() {
			if restore := s.expectOK("Qqemu.PhyMemMode:0"); restore != nil {
				s.protocol.close(restore)
				err = errors.Join(err, fmt.Errorf("restore virtual memory mode: %w", restore))
			}
		}()
	}
	return s.readMemory(addr, data)
}

func (s *Session) UseVirtualMemory() error {
	if err := s.begin(); err != nil {
		return err
	}
	defer s.end()
	return s.expectOK("Qqemu.PhyMemMode:0")
}
