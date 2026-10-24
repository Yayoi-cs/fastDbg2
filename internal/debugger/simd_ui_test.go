package debugger

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"fastdbg2/display"
	"fastdbg2/target"
)

func TestSIMDUIFloatLanesRoundTripWithoutLosingRawBits(t *testing.T) {
	values := []uint64{0, 1 << 63, 1, 0x8000000000000001, math.Float64bits(math.MaxFloat64), math.Float64bits(-math.MaxFloat64), math.Float64bits(math.Inf(1)), math.Float64bits(math.Inf(-1)), 0x7ff8000000000042, 0xfff8000000000037}
	for _, bits := range values {
		for _, width := range []int{80, 120} {
			t.Run(fmt.Sprintf("%016x/%d", bits, width), func(t *testing.T) {
				data := make([]byte, 16)
				binary.LittleEndian.PutUint64(data, bits)
				binary.LittleEndian.PutUint64(data[8:], bits)
				before := bytes.Clone(data)
				var output bytes.Buffer
				controller := &Controller{out: &output}
				if err := controller.writeXMMWidth(context.Background(), 15, data, width); err != nil {
					t.Fatal(err)
				}
				text := output.String()
				if !bytes.Equal(data, before) || !strings.Contains(text, fmt.Sprintf("%016x %016x", bits, bits)) {
					t.Fatalf("raw 128-bit payload lost: %q", text)
				}
				match := regexp.MustCompile(`f64-le:\[([^\]]+)\]`).FindStringSubmatch(text)
				if len(match) != 2 {
					t.Fatalf("explicit lane interpretation missing: %q", text)
				}
				lanes := strings.Fields(match[1])
				if len(lanes) != 2 {
					t.Fatal(text)
				}
				for _, lane := range lanes {
					value, err := strconv.ParseFloat(lane, 64)
					if err != nil || len(lane) > 24 {
						t.Fatalf("unbounded/invalid lane %q: %v", lane, err)
					}
					if math.IsNaN(math.Float64frombits(bits)) {
						if !math.IsNaN(value) {
							t.Fatal("NaN was represented as a finite value")
						}
					} else if math.Float64bits(value) != bits {
						t.Fatalf("lane rounded or changed sign: %q bits=%016x want=%016x", lane, math.Float64bits(value), bits)
					}
				}
				for _, line := range strings.Split(text, "\n") {
					if display.VisibleWidth(line) > width {
						t.Fatalf("lane row exceeds %d columns: %q", width, line)
					}
				}
			})
		}
	}
}

func TestSIMDUIRegisterStylesDoNotAlterPlainPayloads(t *testing.T) {
	data := make([]byte, 16)
	binary.LittleEndian.PutUint64(data, math.Float64bits(-math.MaxFloat64))
	binary.LittleEndian.PutUint64(data[8:], math.Float64bits(math.MaxFloat64))
	var plain, colored bytes.Buffer
	renderer, err := display.NewRenderer(display.Options{Mode: display.ColorAlways})
	if err != nil {
		t.Fatal(err)
	}
	for _, controller := range []*Controller{{out: &plain}, {out: &colored, renderer: renderer}} {
		if err := controller.writeXMMWidth(context.Background(), 0, data, 80); err != nil {
			t.Fatal(err)
		}
		if err := controller.writeYMMWidth(context.Background(), 0, data, data, 80); err != nil {
			t.Fatal(err)
		}
	}
	if vmmapTestSGR.ReplaceAllString(colored.String(), "") != plain.String() || !strings.Contains(colored.String(), "XMM0  : ") || !strings.Contains(colored.String(), "YMM0  : ") || strings.Contains(colored.String(), "\x1b[") {
		t.Fatalf("styles changed values or omitted register identity: %q", colored.String())
	}
	if strings.Count(plain.String(), "\n") != 3 || !strings.Contains(plain.String(), "\n        f64-le:[") {
		t.Fatalf("large lanes were not aligned on a continuation row: %q", plain.String())
	}
}

func TestSIMDUIExtendedFeatureNamesRemainBoundedAndComplete(t *testing.T) {
	controller, fixture, output := newSIMDTestController(target.ExtendedFormatXSave)
	state, err := decodeSIMDState(fixture.state)
	if err != nil {
		t.Fatal(err)
	}
	state.features = math.MaxUint64
	if err := controller.writeSIMD(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(output.String(), "\n") {
		if display.VisibleWidth(line) > display.DefaultWidth {
			t.Fatalf("feature metadata exceeds output width: %q", line)
		}
	}
	if !strings.Contains(output.String(), "0xffffffffffffffff") || !strings.Contains(strings.ReplaceAll(output.String(), "\n    ", ""), "component63") {
		t.Fatalf("known feature mask/names were truncated: %q", output.String())
	}
}
