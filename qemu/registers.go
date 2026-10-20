package qemu

import (
	"bytes"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"fastdbg2/qemu/aarch64"
	"fastdbg2/qemu/amd64"
	"fastdbg2/qemu/internal/arch"
	"fastdbg2/target"
)

type registerDefinition struct {
	number  uint32
	name    string
	bits    int
	feature string
}

type descriptionNode struct {
	XMLName  xml.Name
	Attrs    []xml.Attr        `xml:",any,attr"`
	Text     string            `xml:",chardata"`
	Children []descriptionNode `xml:",any"`
}

func (n descriptionNode) attr(name string) (string, error) {
	var value string
	found := false
	for _, attr := range n.Attrs {
		if attr.Name.Local != name || attr.Name.Space != "" {
			continue
		}
		if found {
			return "", fmt.Errorf("%w: duplicate XML attribute %s", ErrProtocol, name)
		}
		value, found = attr.Value, true
	}
	return value, nil
}

func (s *Session) loadRegisters() error {
	const xmlLimit = 4 << 20
	architecture := ""
	featureName := ""
	var next uint64
	total := 0
	active := make(map[string]bool)
	features := make(map[string]bool)
	names := make(map[string]bool)
	numbers := make(map[uint32]bool)
	var load func(string, int, string) error
	var visit func(descriptionNode, int, string) error
	visit = func(node descriptionNode, depth int, parent string) error {
		if depth > 32 {
			return fmt.Errorf("%w: target XML nesting limit", target.ErrUnsupported)
		}
		switch node.XMLName.Local {
		case "target":
			if parent != "" {
				return fmt.Errorf("%w: nested target XML", ErrProtocol)
			}
			version, err := node.attr("version")
			if err != nil {
				return err
			}
			if version != "" && version != "1.0" {
				return fmt.Errorf("%w: target XML version %q", target.ErrUnsupported, version)
			}
		case "architecture":
			if parent != "target" || architecture != "" || len(node.Children) != 0 {
				return fmt.Errorf("%w: invalid architecture XML", ErrProtocol)
			}
			architecture = strings.TrimSpace(node.Text)
			return nil
		case "osabi", "compatible":
			if parent != "target" {
				return fmt.Errorf("%w: invalid target metadata", ErrProtocol)
			}
			return nil
		case "feature":
			if parent != "target" {
				return fmt.Errorf("%w: invalid feature XML", ErrProtocol)
			}
			name, err := node.attr("name")
			if err != nil {
				return err
			}
			if name == "" || features[name] {
				return fmt.Errorf("%w: missing or duplicate feature name", ErrProtocol)
			}
			features[name] = true
			previous := featureName
			featureName = name
			defer func() { featureName = previous }()
		case "include":
			if (parent != "target" && parent != "feature") || (node.XMLName.Space != "xi" && node.XMLName.Space != "http://www.w3.org/2001/XInclude") {
				return fmt.Errorf("%w: unsupported XML inclusion", target.ErrUnsupported)
			}
			href, err := node.attr("href")
			if err != nil {
				return err
			}
			mode, err := node.attr("parse")
			if err != nil {
				return err
			}
			if mode != "" && mode != "xml" {
				return fmt.Errorf("%w: non-XML inclusion", target.ErrUnsupported)
			}
			pointer, err := node.attr("xpointer")
			if err != nil {
				return err
			}
			if pointer != "" || len(node.Children) != 0 {
				return fmt.Errorf("%w: partial or fallback XML inclusion", target.ErrUnsupported)
			}
			if href == "" || strings.ContainsAny(href, ":,#\x00\r\n") {
				return fmt.Errorf("%w: invalid XML annex", ErrProtocol)
			}
			return load(href, depth+1, parent)
		case "reg":
			if parent != "feature" || len(node.Children) != 0 {
				return fmt.Errorf("%w: invalid register XML", ErrProtocol)
			}
			name, err := node.attr("name")
			if err != nil {
				return err
			}
			width, err := node.attr("bitsize")
			if err != nil {
				return err
			}
			bits, err := strconv.ParseUint(width, 0, 31)
			if err != nil || bits == 0 {
				return fmt.Errorf("%w: invalid register width", ErrProtocol)
			}
			if bits%8 != 0 || bits/8 > uint64(s.protocol.limit) {
				return fmt.Errorf("%w: register width %d", target.ErrUnsupported, bits)
			}
			position, err := node.attr("regnum")
			if err != nil {
				return err
			}
			if position != "" {
				next, err = strconv.ParseUint(position, 0, 32)
				if err != nil {
					return fmt.Errorf("%w: invalid register number", ErrProtocol)
				}
			}
			if next > uint64(^uint32(0)) || name == "" || names[name] || numbers[uint32(next)] {
				return fmt.Errorf("%w: invalid or duplicate register", ErrProtocol)
			}
			names[name], numbers[uint32(next)] = true, true
			s.registers = append(s.registers, registerDefinition{number: uint32(next), name: name, bits: int(bits), feature: featureName})
			next++
			return nil
		case "vector", "union", "struct", "flags", "enum":
			if parent != "feature" {
				return fmt.Errorf("%w: invalid register type XML", ErrProtocol)
			}
			return nil
		default:
			return fmt.Errorf("%w: target XML element %s", target.ErrUnsupported, node.XMLName.Local)
		}
		for _, child := range node.Children {
			if err := visit(child, depth+1, node.XMLName.Local); err != nil {
				return err
			}
		}
		return nil
	}
	load = func(annex string, depth int, parent string) error {
		if depth > 32 || active[annex] {
			return fmt.Errorf("%w: recursive target XML inclusion", ErrProtocol)
		}
		active[annex] = true
		defer delete(active, annex)
		var document []byte
		for {
			length := min(1024, (s.protocol.limit-1)/2)
			data, err := s.request(fmt.Sprintf("qXfer:features:read:%s:%x,%x", annex, len(document), length))
			if err != nil {
				return err
			}
			if len(data) == 0 {
				return fmt.Errorf("%w: XML annex %s", target.ErrUnsupported, annex)
			}
			if (data[0] != 'm' && data[0] != 'l') || len(data)-1 > length || (data[0] == 'm' && len(data) == 1) {
				return fmt.Errorf("%w: invalid XML transfer", ErrProtocol)
			}
			total += len(data) - 1
			if total > xmlLimit {
				return fmt.Errorf("%w: target XML size limit", target.ErrUnsupported)
			}
			document = append(document, data[1:]...)
			if data[0] == 'l' {
				break
			}
		}
		decoder := xml.NewDecoder(bytes.NewReader(document))
		var node descriptionNode
		if err := decoder.Decode(&node); err != nil {
			return fmt.Errorf("%w: target XML: %v", ErrProtocol, err)
		}
		for {
			token, err := decoder.Token()
			if err == io.EOF {
				break
			}
			if err != nil {
				return fmt.Errorf("%w: trailing target XML: %v", ErrProtocol, err)
			}
			if text, ok := token.(xml.CharData); !ok || strings.TrimSpace(string(text)) != "" {
				return fmt.Errorf("%w: trailing target XML", ErrProtocol)
			}
		}
		return visit(node, depth, parent)
	}
	if err := load("target.xml", 0, ""); err != nil {
		return err
	}
	for _, profile := range []arch.Descriptor{amd64.Descriptor(), aarch64.Descriptor()} {
		if architecture == profile.XMLArchitecture {
			s.profile = profile
			break
		}
	}
	if s.profile.Architecture == "" {
		return fmt.Errorf("%w: target architecture %q", target.ErrUnsupported, architecture)
	}
	if s.registerByteOrder == target.ByteOrderUnknown {
		s.registerByteOrder = s.profile.FixedRegisterByteOrder
	}
	if s.registerByteOrder == target.ByteOrderUnknown {
		return fmt.Errorf("%w: %s requires an explicit RegisterByteOrder", target.ErrUnknown, architecture)
	}
	if fixed := s.profile.FixedRegisterByteOrder; fixed != target.ByteOrderUnknown && fixed != s.registerByteOrder {
		return fmt.Errorf("%w: %s register byte order %s", target.ErrUnsupported, architecture, s.registerByteOrder)
	}
	definitions := make([]arch.Register, len(s.registers))
	for i, reg := range s.registers {
		definitions[i] = arch.Register{Name: reg.name, Bits: reg.bits, Feature: reg.feature}
	}
	if err := s.profile.ValidateRegisters(definitions); err != nil {
		return err
	}
	if len(s.registers) == 0 {
		return fmt.Errorf("%w: target register layout is missing", target.ErrUnknown)
	}
	slices.SortFunc(s.registers, func(a, b registerDefinition) int {
		if a.number < b.number {
			return -1
		}
		if a.number > b.number {
			return 1
		}
		return 0
	})
	return nil
}

func decodeRegister(value string, bits int) ([]byte, bool, error) {
	if len(value) != bits/4 {
		return nil, false, fmt.Errorf("%w: register size mismatch", ErrProtocol)
	}
	if strings.Count(value, "x") == len(value) {
		return nil, false, nil
	}
	if strings.ContainsRune(value, 'x') {
		return nil, false, fmt.Errorf("%w: partially unavailable register", target.ErrUnsupported)
	}
	data, err := hex.DecodeString(value)
	if err != nil {
		return nil, false, fmt.Errorf("%w: malformed register bytes", ErrProtocol)
	}
	return data, true, nil
}

func (s *Session) ReadRegisters() ([]target.Register, error) {
	if err := s.begin(); err != nil {
		return nil, err
	}
	defer s.end()
	expected := 0
	complete := true
	for i, reg := range s.registers {
		if reg.bits/4 > s.protocol.limit {
			return nil, fmt.Errorf("%w: register %s exceeds receive limit", target.ErrUnsupported, reg.name)
		}
		if reg.number != uint32(i) || reg.bits/4 > s.protocol.limit-expected {
			complete = false
		}
		if complete {
			expected += reg.bits / 4
		}
	}
	if err := s.selectThread(); err != nil {
		return nil, err
	}
	if complete {
		data, err := s.request("g")
		if err != nil {
			return nil, err
		}
		if len(data) == expected {
			registers := make([]target.Register, 0, len(s.registers))
			offset := 0
			for _, reg := range s.registers {
				length := reg.bits / 4
				value, available, err := decodeRegister(string(data[offset:offset+length]), reg.bits)
				if err != nil {
					return nil, fmt.Errorf("read register %s: %w", reg.name, err)
				}
				registers = append(registers, target.Register{Name: reg.name, Bits: reg.bits, Data: value, Available: available})
				offset += length
			}
			return registers, nil
		}
	}
	registers := make([]target.Register, 0, len(s.registers))
	for _, reg := range s.registers {
		data, err := s.request(fmt.Sprintf("p%x", reg.number))
		if err != nil {
			return nil, fmt.Errorf("read register %s: %w", reg.name, err)
		}
		if len(data) == 0 {
			return nil, fmt.Errorf("%w: register %s (p%x)", target.ErrUnsupported, reg.name, reg.number)
		}
		value, available, err := decodeRegister(string(data), reg.bits)
		if err != nil {
			return nil, fmt.Errorf("read register %s: %w", reg.name, err)
		}
		registers = append(registers, target.Register{Name: reg.name, Bits: reg.bits, Data: value, Available: available})
	}
	return registers, nil
}

func (s *Session) WriteRegisters(registers []target.Register) error {
	if err := s.begin(); err != nil {
		return err
	}
	defer s.end()
	definitions := make(map[string]registerDefinition, len(s.registers))
	for _, reg := range s.registers {
		definitions[reg.name] = reg
	}
	seen := make(map[string]bool, len(registers))
	commands := make([]string, len(registers))
	for i, reg := range registers {
		definition, exists := definitions[reg.Name]
		if !exists || seen[reg.Name] || reg.Bits != definition.bits || len(reg.Data) != definition.bits/8 || !reg.Available {
			return fmt.Errorf("%w: register %q", target.ErrInvalidArgument, reg.Name)
		}
		seen[reg.Name] = true
		commands[i] = fmt.Sprintf("P%x=%s", definition.number, hex.EncodeToString(reg.Data))
		if len(commands[i]) > s.packetSize {
			return fmt.Errorf("%w: P packet exceeds PacketSize", target.ErrUnsupported)
		}
	}
	if len(commands) == 0 {
		return nil
	}
	if err := s.selectThread(); err != nil {
		return err
	}
	s.changed()
	for i, command := range commands {
		if err := s.expectOK(command); err != nil {
			return &target.PartialError{Op: "write registers", Completed: i, Total: len(registers), Err: err}
		}
	}
	return nil
}
