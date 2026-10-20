package qemu

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

var ErrProtocol = errors.New("invalid remote protocol")

type RemoteError struct {
	Command string
	Code    byte
}

func (e *RemoteError) Error() string {
	return fmt.Sprintf("remote %s failed with E%02x", e.Command, e.Code)
}

type packet struct {
	kind  byte
	data  []byte
	valid bool
}

type protocol struct {
	conn       net.Conn
	incoming   chan packet
	done       chan struct{}
	readerDone chan struct{}
	writeMu    sync.Mutex
	errMu      sync.Mutex
	closeOnce  sync.Once
	err        error
	timeout    time.Duration
	limit      int
}

func newProtocol(conn net.Conn, timeout time.Duration, limit int) *protocol {
	p := &protocol{
		conn: conn, incoming: make(chan packet, 16), done: make(chan struct{}),
		readerDone: make(chan struct{}), timeout: timeout, limit: limit,
	}
	go p.readLoop()
	return p
}

func (p *protocol) close(err error) {
	p.closeOnce.Do(func() {
		p.errMu.Lock()
		p.err = err
		p.errMu.Unlock()
		close(p.done)
		p.conn.Close()
	})
}

func (p *protocol) failure() error {
	p.errMu.Lock()
	defer p.errMu.Unlock()
	return p.err
}

func (p *protocol) readLoop() {
	defer close(p.readerDone)
	defer close(p.incoming)
	r := bufio.NewReader(p.conn)
	for {
		b, err := r.ReadByte()
		if err != nil {
			p.close(err)
			return
		}
		token := packet{kind: b, valid: true}
		switch b {
		case '+', '-':
		case '$':
			var sum byte
			escaped := false
			runCount := false
			for {
				b, err = r.ReadByte()
				if err != nil {
					p.close(err)
					return
				}
				if b == '#' && !escaped {
					break
				}
				if b == '$' && !escaped {
					p.close(fmt.Errorf("%w: nested packet", ErrProtocol))
					return
				}
				if len(token.data) == p.limit {
					p.close(fmt.Errorf("%w: packet exceeds receive limit", ErrProtocol))
					return
				}
				token.data = append(token.data, b)
				sum += b
				if escaped {
					escaped = false
				} else if runCount {
					runCount = false
				} else {
					escaped = b == '}'
					runCount = b == '*'
				}
			}
			var checksum [2]byte
			if _, err = io.ReadFull(r, checksum[:]); err != nil {
				p.close(err)
				return
			}
			var decoded [1]byte
			if _, err = hex.Decode(decoded[:], checksum[:]); err != nil {
				p.close(fmt.Errorf("%w: malformed checksum", ErrProtocol))
				return
			}
			token.valid = decoded[0] == sum
		default:
			p.close(fmt.Errorf("%w: unexpected framing byte %#x", ErrProtocol, b))
			return
		}
		select {
		case p.incoming <- token:
		case <-p.done:
			return
		}
	}
}

func encodePacket(data []byte) []byte {
	frame := make([]byte, 1, len(data)+4)
	frame[0] = '$'
	var sum byte
	for _, b := range data {
		switch b {
		case '$', '#', '}', '*':
			frame = append(frame, '}', b^0x20)
			sum += '}' + (b ^ 0x20)
		default:
			frame = append(frame, b)
			sum += b
		}
	}
	const digits = "0123456789abcdef"
	return append(frame, '#', digits[sum>>4], digits[sum&15])
}

func decodePacket(data []byte, limit int) ([]byte, error) {
	decoded := make([]byte, 0, len(data))
	for i := 0; i < len(data); i++ {
		switch data[i] {
		case '}':
			i++
			if i == len(data) {
				return nil, fmt.Errorf("%w: incomplete escape", ErrProtocol)
			}
			decoded = append(decoded, data[i]^0x20)
		case '*':
			i++
			if len(decoded) == 0 || i == len(data) || data[i] < 32 || data[i] > 126 || data[i] == '#' || data[i] == '$' {
				return nil, fmt.Errorf("%w: invalid run-length encoding", ErrProtocol)
			}
			n := int(data[i]) - 29
			if n > limit-len(decoded) {
				return nil, fmt.Errorf("%w: decoded packet exceeds receive limit", ErrProtocol)
			}
			b := decoded[len(decoded)-1]
			for range n {
				decoded = append(decoded, b)
			}
		default:
			decoded = append(decoded, data[i])
		}
		if len(decoded) > limit {
			return nil, fmt.Errorf("%w: decoded packet exceeds receive limit", ErrProtocol)
		}
	}
	return decoded, nil
}

func (p *protocol) write(data []byte) error {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	select {
	case <-p.done:
		return p.failure()
	default:
	}
	if err := p.conn.SetWriteDeadline(time.Now().Add(p.timeout)); err != nil {
		p.close(err)
		return err
	}
	for len(data) != 0 {
		n, err := p.conn.Write(data)
		if err == nil && n == 0 {
			err = io.ErrNoProgress
		}
		if err != nil {
			p.close(err)
			return err
		}
		data = data[n:]
	}
	return nil
}

func (p *protocol) next(deadline <-chan time.Time) (packet, error) {
	select {
	case <-deadline:
		err := fmt.Errorf("qemu response timeout: %w", context.DeadlineExceeded)
		p.close(err)
		return packet{}, err
	default:
	}
	select {
	case token, ok := <-p.incoming:
		if !ok {
			return packet{}, p.failure()
		}
		return token, nil
	default:
	}
	select {
	case token, ok := <-p.incoming:
		if !ok {
			return packet{}, p.failure()
		}
		return token, nil
	case <-deadline:
		err := fmt.Errorf("qemu response timeout: %w", context.DeadlineExceeded)
		p.close(err)
		return packet{}, err
	case <-p.done:
		select {
		case token, ok := <-p.incoming:
			if ok {
				return token, nil
			}
		default:
		}
		return packet{}, p.failure()
	}
}

func (p *protocol) send(command string, noAck bool) error {
	frame := encodePacket([]byte(command))
	if err := p.write(frame); err != nil {
		return err
	}
	if noAck {
		return nil
	}
	timer := time.NewTimer(p.timeout)
	defer timer.Stop()
	for tries := 0; tries < 3; tries++ {
		token, err := p.next(timer.C)
		if err != nil {
			return err
		}
		if token.kind == '+' {
			return nil
		}
		if token.kind != '-' {
			err = fmt.Errorf("%w: response before acknowledgment", ErrProtocol)
			p.close(err)
			return err
		}
		if err := p.write(frame); err != nil {
			return err
		}
	}
	err := fmt.Errorf("%w: command retransmission limit", ErrProtocol)
	p.close(err)
	return err
}

func (p *protocol) reply(noAck, running bool, console func([]byte) error) ([]byte, error) {
	var deadline <-chan time.Time
	if !running {
		timer := time.NewTimer(p.timeout)
		defer timer.Stop()
		deadline = timer.C
	}
	badChecksums := 0
	for {
		token, err := p.next(deadline)
		if err != nil {
			return nil, err
		}
		if token.kind != '$' {
			err = fmt.Errorf("%w: unexpected acknowledgment", ErrProtocol)
			p.close(err)
			return nil, err
		}
		if !token.valid {
			badChecksums++
			if noAck || badChecksums == 3 {
				err = fmt.Errorf("%w: checksum mismatch", ErrProtocol)
				p.close(err)
				return nil, err
			}
			if err := p.write([]byte{'-'}); err != nil {
				return nil, err
			}
			continue
		}
		if !noAck {
			if err := p.write([]byte{'+'}); err != nil {
				return nil, err
			}
		}
		data, err := decodePacket(token.data, p.limit)
		if err != nil {
			p.close(err)
			return nil, err
		}
		if len(data) > 0 && data[0] == 'O' && string(data) != "OK" {
			output, err := hex.DecodeString(string(data[1:]))
			if err != nil {
				err = fmt.Errorf("%w: malformed console output", ErrProtocol)
				p.close(err)
				return nil, err
			}
			if err := console(output); err != nil {
				p.close(err)
				return nil, err
			}
			continue
		}
		return data, nil
	}
}
