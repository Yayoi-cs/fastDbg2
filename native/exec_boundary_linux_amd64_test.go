package native

import (
	"errors"
	"fastdbg2/target"
	"fmt"
	"testing"

	"golang.org/x/sys/unix"
)

func boundarySession(t *testing.T, bits int, first string) (*Session, target.Address) {
	t.Helper()
	path, entry := coreAssembly(t, bits, ".text\n.global _start\n_start:\n"+first+"\n nop\n jmp _start\n")
	s, err := Launch(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s, entry
}

func TestExecBoundaryCancellationPreservesUserBreakpoints(t *testing.T) {
	s, entry := boundarySession(t, 64, "nop")
	if err := s.AddBreakpoint(entry + 1); err != nil {
		t.Fatal(err)
	}
	err := command(s, func(e *engine) error {
		current := e.threads[s.pid]
		bp, err := e.installExecBoundary(current, entry)
		if err != nil {
			return err
		}
		if bp == nil || bp.boundary != current || !bp.armed {
			return errors.New("temporary boundary was not owned and armed")
		}
		if err := e.cancelExecBoundaries(); err != nil {
			return err
		}
		if _, exists := current.process.space.breakpoints[entry]; exists {
			return errors.New("canceled boundary remained registered")
		}
		user := current.process.space.breakpoints[entry+1]
		if user == nil || !user.armed || user.boundary != nil {
			return errors.New("boundary cleanup modified a user breakpoint")
		}
		value, err := e.readByte(current.tid, entry)
		if err != nil || value != 0x90 {
			return errors.New("boundary cleanup did not restore the original byte")
		}
		pc, err := e.readPC(current.tid)
		if err != nil || pc != entry {
			return errors.New("cleanup rewound a PC without a breakpoint hit")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestExecBoundaryNeverOwnsAnExistingBreakpoint(t *testing.T) {
	for _, managed := range []bool{false, true} {
		t.Run(fmt.Sprint(managed), func(t *testing.T) {
			first := ".byte 0xcc"
			if managed {
				first = "nop"
			}
			s, entry := boundarySession(t, 64, first)
			if managed {
				if err := s.AddBreakpoint(entry); err != nil {
					t.Fatal(err)
				}
			}
			err := command(s, func(e *engine) error {
				current := e.threads[s.pid]
				beforeRegisters, beforeMemory := current.registerRevision, current.process.space.revision
				bp, err := e.installExecBoundary(current, entry)
				if err != nil || bp != nil {
					return errors.New("existing breakpoint became an internal boundary")
				}
				if current.registerRevision != beforeRegisters || current.process.space.revision != beforeMemory {
					return errors.New("existing breakpoint caused a mutation")
				}
				return e.cancelExecBoundaries()
			})
			if err != nil {
				t.Fatal(err)
			}
			stop, err := s.Continue(target.Signal{})
			want := target.StopSignal
			if managed {
				want = target.StopBreakpoint
			}
			if err != nil || stop.Reason != want || stop.RawPC == nil || *stop.RawPC != entry+1 {
				t.Fatalf("existing breakpoint was consumed: stop=%+v error=%v", stop, err)
			}
		})
	}
}

func TestExecBoundaryConsumesOnlyProvenHits(t *testing.T) {
	for _, bits := range []int{32, 64} {
		for _, cancel := range []bool{false, true} {
			t.Run(fmt.Sprintf("bits%d_cancel%t", bits, cancel), func(t *testing.T) {
				s, entry := boundarySession(t, bits, "nop")
				err := command(s, func(e *engine) error {
					current := e.threads[s.pid]
					bp, err := e.installExecBoundary(current, entry)
					if err != nil || bp == nil {
						return errors.Join(err, errors.New("missing boundary"))
					}
					if err := e.consumeExecBoundary(current, bp); !errors.Is(err, target.ErrStale) {
						return errors.New("boundary was consumed without a kernel hit")
					}
					if err := unix.PtraceCont(current.tid, 0); err != nil {
						return err
					}
					var status unix.WaitStatus
					for {
						_, err = unix.Wait4(current.tid, &status, unix.WALL, nil)
						if !errors.Is(err, unix.EINTR) {
							break
						}
					}
					if err != nil || !status.Stopped() || status.StopSignal() != unix.SIGTRAP || status.TrapCause() != 0 {
						return errors.Join(err, errors.New("boundary did not produce a real trap"))
					}
					info, err := readSignalInfo(current.tid)
					if err != nil || info == nil || info.Code != 1 && info.Code != 128 {
						return errors.Join(err, errors.New("boundary trap did not identify INT3"))
					}
					pc, err := e.readPC(current.tid)
					if err != nil {
						return err
					}
					if err := e.recordBreakpointHit(current, entry, pc); err != nil {
						return err
					}
					if cancel {
						err = e.cancelExecBoundaries()
					} else {
						err = e.consumeExecBoundary(current, bp)
					}
					if err != nil {
						return err
					}
					pc, err = e.readPC(current.tid)
					if err != nil || pc != entry || current.hit != nil || current.suspended != nil || len(current.process.space.breakpoints) != 0 {
						return errors.New("real hit cleanup did not restore the pre-instruction state")
					}
					value, err := e.readByte(current.tid, entry)
					if err != nil || value != 0x90 {
						return errors.New("temporary INT3 remained after cleanup")
					}
					return nil
				})
				if err != nil {
					t.Fatal(err)
				}
				stop, err := s.Step(target.Signal{})
				if err != nil || stop.Reason != target.StopStep || !stop.StepCompleted || stop.RawPC == nil || *stop.RawPC != entry+1 {
					t.Fatalf("first actual user instruction: stop=%+v error=%v", stop, err)
				}
			})
		}
	}
}

func TestExecBoundaryFailedCleanupRetainsOwnership(t *testing.T) {
	s, entry := boundarySession(t, 64, "nop")
	err := command(s, func(e *engine) error {
		current := e.threads[s.pid]
		bp, err := e.installExecBoundary(current, entry)
		if err != nil || bp == nil {
			return errors.Join(err, errors.New("missing boundary"))
		}
		if err := e.writeByte(current.tid, entry, 0x91); err != nil {
			return err
		}
		if err := e.cancelExecBoundaries(); !errors.Is(err, target.ErrStale) {
			return errors.New("changed boundary byte was overwritten")
		}
		if current.process.space.breakpoints[entry] != bp || bp.boundary != current || e.unsupported == nil {
			return errors.New("failed boundary cleanup lost ownership or allowed resumption")
		}
		if err := e.writeByte(current.tid, entry, 0xcc); err != nil {
			return err
		}
		if err := e.cancelExecBoundaries(); err != nil {
			return err
		}
		if len(current.process.space.breakpoints) != 0 {
			return errors.New("cleanup retry retained the temporary patch")
		}
		value, err := e.readByte(current.tid, entry)
		if err != nil || value != 0x90 {
			return errors.New("cleanup retry did not restore the instruction")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
