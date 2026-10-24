package debugger

import (
	"context"
	"errors"
	"math"
	"strings"
	"unicode"
	"unicode/utf8"

	"fastdbg2/display"
	"fastdbg2/target"
)

const (
	maxAddressTextBytes = 256
	maxAddressTextWidth = 64
	maxAddressTextRead  = 32 * 1024
	maxAddressTextCalls = 2048
	maxAddressTextChunk = 32
)

type addressTextSource struct {
	address target.Address
	known   bool
}

func (walker *addressWalker) readableTextBytes(address target.Address, limit int) int {
	index := walker.mapIndex(address)
	if index < 0 || !walker.maps[index].Read || limit <= 0 {
		return 0
	}
	available := 0
	for index < len(walker.maps) {
		mapping := walker.maps[index]
		if !mapping.Read || mapping.Start > address {
			break
		}
		n := int(min(uint64(limit-available), uint64(mapping.End-address)))
		available += n
		if available == limit {
			break
		}
		address = mapping.End
		index++
	}
	return available
}

func (walker *addressWalker) rememberTextBytes(address target.Address, data []byte) {
	for index, value := range data {
		current := address + target.Address(index)
		walker.textBytes[current] = value
		delete(walker.textFailed, current)
	}
}

func (walker *addressWalker) textWord(address target.Address) (addressWalkWord, bool) {
	if uint64(address) > walker.abi().maximum-uint64(walker.abi().word-1) {
		return addressWalkWord{}, false
	}
	word := addressWalkWord{n: walker.abi().word}
	for index := range word.data[:walker.abi().word] {
		value, ok := walker.textBytes[address+target.Address(index)]
		if !ok {
			return addressWalkWord{}, false
		}
		word.data[index] = value
	}
	word.value = inspectionWord(word.data[:walker.abi().word])
	return word, true
}

func (walker *addressWalker) textByte(ctx context.Context, address target.Address, remaining int) (byte, bool, error) {
	if err := walker.ready(ctx); err != nil {
		return 0, false, err
	}
	if walker.readableTextBytes(address, 1) == 0 {
		return 0, false, nil
	}
	if value, ok := walker.textBytes[address]; ok {
		return value, true, nil
	}
	if walker.textFailed[address] || walker.textRead == maxAddressTextRead || walker.textCalls == maxAddressTextCalls {
		return 0, false, nil
	}
	if word, ok := walker.cache[address]; ok && word.err != nil {
		return 0, false, nil
	}
	length := walker.readableTextBytes(address, min(remaining, maxAddressTextChunk, maxAddressTextRead-walker.textRead))
	for index := 1; index < length; index++ {
		current := address + target.Address(index)
		if _, exists := walker.textBytes[current]; exists || walker.textFailed[current] {
			length = index
			break
		}
	}
	if length == 0 {
		return 0, false, nil
	}
	data := make([]byte, length)
	walker.textRead += length
	walker.textCalls++
	n, err := walker.reader.ReadSpaceMemory(walker.memory, address, data)
	data, err = inspectionConfirmedBytes(data, n, err)
	if canceled := walker.ready(ctx); canceled != nil {
		err = errors.Join(err, canceled)
	}
	if addressWalkFatal(err) {
		walker.fatal = err
		return 0, false, err
	}
	if err != nil {
		for index := 0; index < length; index++ {
			walker.textFailed[address+target.Address(index)] = true
		}
		return 0, false, nil
	}
	walker.rememberTextBytes(address, data)
	return data[0], true, nil
}

func (walker *addressWalker) visibleText(ctx context.Context, address target.Address) (string, error) {
	if err := walker.ready(ctx); err != nil {
		return "", err
	}
	if text, exists := walker.textCache[address]; exists {
		return text, nil
	}
	data := make([]byte, 0, maxAddressTextBytes-1)
	validated := 0
	for offset := 0; offset < maxAddressTextBytes; offset++ {
		if uint64(address) > math.MaxUint64-uint64(offset) {
			break
		}
		value, known, err := walker.textByte(ctx, address+target.Address(offset), maxAddressTextBytes-offset)
		if err != nil {
			return "", err
		}
		if !known {
			break
		}
		if value == 0 {
			if len(data) != 0 && validated == len(data) {
				text := addressTextQuote(string(data))
				walker.textCache[address] = text
				return text, nil
			}
			break
		}
		data = append(data, value)
		for validated < len(data) && utf8.FullRune(data[validated:]) {
			r, size := utf8.DecodeRune(data[validated:])
			if r == utf8.RuneError && size == 1 || !unicode.IsPrint(r) {
				walker.textCache[address] = ""
				return "", nil
			}
			validated += size
		}
	}
	walker.textCache[address] = ""
	return "", nil
}

func addressTextQuote(text string) string {
	var escaped strings.Builder
	for _, r := range text {
		if r == '\'' || r == '\\' {
			escaped.WriteByte('\\')
		}
		escaped.WriteRune(r)
	}
	if quoted := "'" + escaped.String() + "'"; display.VisibleWidth(quoted) <= maxAddressTextWidth {
		return quoted
	}
	escaped.Reset()
	columns := 0
	for _, r := range text {
		part := string(r)
		if r == '\'' || r == '\\' {
			part = "\\" + part
		}
		width := display.VisibleWidth(part)
		if columns+width > maxAddressTextWidth-5 {
			break
		}
		escaped.WriteString(part)
		columns += width
	}
	return "'" + escaped.String() + "'..."
}

func (walker *addressWalker) leafText(ctx context.Context, address target.Address, source addressTextSource) (string, error) {
	if available := walker.readableTextBytes(address, walker.abi().word); available > 0 && available < walker.abi().word {
		source = addressTextSource{address: address, known: true}
	}
	if !source.known {
		return "", walker.ready(ctx)
	}
	text, err := walker.visibleText(ctx, source.address)
	if err != nil {
		return "", err
	}
	if err := walker.ready(ctx); err != nil {
		return "", err
	}
	if text == "" {
		return "", nil
	}
	index := walker.mapIndex(source.address)
	if index >= 0 && walker.mapErr == nil {
		mapping := walker.maps[index]
		text = walker.renderer.PermissionText(text, mapping.Read, mapping.Write, mapping.Execute)
	}
	return " " + text, nil
}
