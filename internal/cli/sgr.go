package cli

import (
	"io"
	"sync"
)

type sgrWriter struct {
	mu     sync.Mutex
	target io.Writer
	parser sgrParser
	closed bool
	err    error
}

func (w *sgrWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return 0, w.err
	}
	if w.closed {
		return 0, io.ErrClosedPipe
	}
	output, offsets := w.parser.Feed(p)
	if len(output) == 0 {
		return len(p), nil
	}
	n, err := w.target.Write(output)
	if n < 0 || n > len(output) {
		n = 0
	}
	if err == nil && n != len(output) {
		err = io.ErrShortWrite
	}
	if err != nil {
		w.err = err
		if n == len(output) {
			return len(p), err
		}
		if n > 0 {
			return offsets[n-1], err
		}
		return 0, err
	}
	return len(p), nil
}

func (w *sgrWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return w.err
	}
	w.closed = true
	if w.err != nil || len(w.parser.pending) == 0 {
		return w.err
	}
	n, err := w.target.Write(w.parser.pending)
	if err == nil && n != len(w.parser.pending) {
		err = io.ErrShortWrite
	}
	w.err = err
	return err
}

type sgrParser struct {
	state       byte
	pending     []byte
	offsets     []int
	header      int
	sgr         bool
	inString    bool
	osc         bool
	stringESC   bool
	utf8Pending int
}

func (s *sgrParser) Feed(input []byte) ([]byte, []int) {
	for i := range s.offsets {
		s.offsets[i] = 0
	}
	var output []byte
	var offsets []int
	emit := func(b byte, offset int) {
		output = append(output, b)
		offsets = append(offsets, offset)
	}
	flush := func() {
		output = append(output, s.pending...)
		offsets = append(offsets, s.offsets...)
		s.pending = s.pending[:0]
		s.offsets = s.offsets[:0]
		s.state = 0
	}
	buffer := func(b byte, offset int) {
		s.pending = append(s.pending, b)
		s.offsets = append(s.offsets, offset)
	}
	for index, b := range input {
		offset := index + 1
		continuation := s.advanceUTF8(b)
		if s.inString {
			emit(b, offset)
			if s.stringESC && b == '\\' || s.osc && b == '\a' || !continuation && b == 0x9c {
				s.inString = false
			}
			s.stringESC = b == '\x1b'
			continue
		}
		if s.state == '[' {
			if b == '\x1b' {
				flush()
				buffer(b, offset)
				s.state = '\x1b'
				continue
			}
			buffer(b, offset)
			switch {
			case b == 0x18 || b == 0x1a:
				flush()
			case b < 0x20 || b == 0x7f:
			case b >= 0x30 && b <= 0x3f:
				if b > '9' && b != ';' && b != ':' {
					s.sgr = false
				}
			case b >= 0x20 && b <= 0x2f:
				s.sgr = false
			case b >= 0x40 && b <= 0x7e:
				if b == 'm' && s.sgr {
					for i := s.header; i < len(s.pending)-1; i++ {
						if s.pending[i] < 0x20 || s.pending[i] == 0x7f {
							emit(s.pending[i], s.offsets[i])
						}
					}
					s.pending = s.pending[:0]
					s.offsets = s.offsets[:0]
					s.state = 0
				} else {
					flush()
				}
			default:
				flush()
			}
			continue
		}
		if s.state == '\x1b' {
			if b == '\x1b' {
				flush()
				buffer(b, offset)
				s.state = '\x1b'
				continue
			}
			buffer(b, offset)
			if b == '[' {
				s.state, s.header, s.sgr = '[', 2, true
			} else {
				flush()
				if b == ']' || b == 'P' || b == 'X' || b == '^' || b == '_' {
					s.inString, s.osc, s.stringESC = true, b == ']', false
				}
			}
			continue
		}
		switch {
		case b == '\x1b':
			buffer(b, offset)
			s.state = '\x1b'
		case !continuation && b == 0x9b:
			buffer(b, offset)
			s.state, s.header, s.sgr = '[', 1, true
		case !continuation && (b == 0x90 || b == 0x98 || b == 0x9d || b == 0x9e || b == 0x9f):
			emit(b, offset)
			s.inString, s.osc, s.stringESC = true, b == 0x9d, false
		default:
			emit(b, offset)
		}
	}
	return output, offsets
}

func (s *sgrParser) advanceUTF8(b byte) bool {
	if s.utf8Pending > 0 && b >= 0x80 && b <= 0xbf {
		s.utf8Pending--
		return true
	}
	s.utf8Pending = 0
	switch {
	case b >= 0xc2 && b <= 0xdf:
		s.utf8Pending = 1
	case b >= 0xe0 && b <= 0xef:
		s.utf8Pending = 2
	case b >= 0xf0 && b <= 0xf4:
		s.utf8Pending = 3
	}
	return false
}
