package native

import (
	"errors"
	"fastdbg2/target"
	"testing"
)

func breakpointTestSpace(id uint64) *addressSpace {
	return &addressSpace{
		ref:         target.SpaceRef{Session: 1, ID: id},
		breakpoints: make(map[target.Address]*breakpoint),
	}
}

func breakpointTestSite(space *addressSpace, addr target.Address, generation uint64, armed bool) *breakpoint {
	bp := &breakpoint{
		addr: addr, original: 0x90, armed: armed, space: space,
		spaceRef: space.ref, generation: generation,
	}
	space.breakpoints[addr] = bp
	space.nextBreakpoint = generation
	return bp
}

func TestBreakpointPatchConfirmation(t *testing.T) {
	for _, test := range []struct {
		name   string
		before byte
		after  byte
		value  byte
		armed  bool
		want   error
	}{
		{"inserted", 0x90, 0xcc, 0xcc, true, nil},
		{"insert-not-applied", 0x90, 0xcc, 0x90, false, nil},
		{"restored", 0xcc, 0x90, 0x90, false, nil},
		{"restore-not-applied", 0xcc, 0x90, 0xcc, true, nil},
		{"unconfirmed", 0xcc, 0x90, 0x91, true, target.ErrStale},
	} {
		t.Run(test.name, func(t *testing.T) {
			bp := &breakpoint{addr: 0x1000, original: 0x90, armed: test.before == 0xcc,
				pending: &breakpointWrite{before: test.before, after: test.after}}
			pending := bp.pending
			if err := bp.confirmWrite(test.value); !errors.Is(err, test.want) {
				t.Fatalf("confirmation=%v want=%v", err, test.want)
			}
			if bp.armed != test.armed {
				t.Fatalf("armed=%v want=%v", bp.armed, test.armed)
			}
			if test.want == nil && bp.pending != nil {
				t.Fatal("confirmed write retained its pending journal")
			}
			if test.want != nil && bp.pending != pending {
				t.Fatal("unconfirmed write lost its pending journal")
			}
		})
	}
	if err := (&breakpoint{}).confirmWrite(0); !errors.Is(err, target.ErrInvalidState) {
		t.Fatalf("missing write accepted: %v", err)
	}
}

func TestBreakpointHitIdentityRejectsAddressReuse(t *testing.T) {
	space := breakpointTestSpace(1)
	bp := breakpointTestSite(space, 0x1000, 1, true)
	p := &process{space: space}
	a := &thread{tid: 1, process: p, hit: &breakpointHit{bp: bp, generation: 1, rawPC: 0x1001}}
	b := &thread{tid: 2, process: p, hit: &breakpointHit{bp: bp, generation: 1, rawPC: 0x1001}}
	for _, current := range []*thread{a, b} {
		if err := validateBreakpointHit(current); err != nil {
			t.Fatalf("valid simultaneous hit: %v", err)
		}
	}
	breakpointTestSite(space, 0x1000, 2, true)
	for _, current := range []*thread{a, b} {
		if err := validateBreakpointHit(current); !errors.Is(err, target.ErrStale) {
			t.Fatalf("old hit applied to replacement site: %v", err)
		}
	}
	space.breakpoints[bp.addr] = bp
	a.hit.generation++
	if err := validateBreakpointHit(a); !errors.Is(err, target.ErrStale) {
		t.Fatalf("generation mismatch accepted: %v", err)
	}
	if err := validateBreakpointHit(b); err != nil {
		t.Fatalf("another thread's hit changed: %v", err)
	}
	space.ref.ID++
	if err := validateBreakpointHit(b); !errors.Is(err, target.ErrStale) {
		t.Fatalf("old image hit accepted: %v", err)
	}
}

func TestBreakpointMutationRequiresStoppedAddressSpace(t *testing.T) {
	space := breakpointTestSpace(1)
	bp := breakpointTestSite(space, 0x1000, 1, true)
	p := &process{space: space}
	a := &thread{tid: 1, process: p, state: target.StateStopped,
		hit: &breakpointHit{bp: bp, generation: 1, rawPC: 0x1001}}
	b := &thread{tid: 2, process: p, state: target.StateRunning}
	e := &engine{threads: map[int]*thread{1: a, 2: b}}
	if err := e.disarm(bp); !errors.Is(err, target.ErrRunning) {
		t.Fatalf("disarm with running peer: %v", err)
	}
	if _, err := e.prepareBreakpointStep(a); !errors.Is(err, target.ErrRunning) {
		t.Fatalf("step prepare with running peer: %v", err)
	}
	if !bp.armed || bp.pending != nil || a.hit == nil || a.suspended != nil || space.stepping != nil {
		t.Fatal("rejected operation changed breakpoint state")
	}
	b.state = target.StateStopped
	space.unknown = true
	if err := e.disarm(bp); !errors.Is(err, target.ErrUnavailable) {
		t.Fatalf("unknown sharing accepted: %v", err)
	}
}

func TestBreakpointCopyPreservesPhysicalState(t *testing.T) {
	from, to := breakpointTestSpace(1), breakpointTestSpace(2)
	a := breakpointTestSite(from, 0x1000, 1, true)
	b := breakpointTestSite(from, 0x2000, 2, false)
	e := &engine{}
	if err := e.copyBreakpoints(from, to); err != nil {
		t.Fatal(err)
	}
	for _, parent := range []*breakpoint{a, b} {
		child := to.breakpoints[parent.addr]
		if child == parent || child == nil || child.armed != parent.armed || child.original != parent.original || child.space != to || child.spaceRef != to.ref {
			t.Fatalf("physical copy=%+v parent=%+v", child, parent)
		}
		if err := validateBreakpoint(child); err != nil {
			t.Fatalf("copied site identity: %v", err)
		}
	}
	to.breakpoints[a.addr].armed = false
	if !a.armed || to.nextBreakpoint != from.nextBreakpoint {
		t.Fatal("child mutation changed parent or lost site sequence")
	}
	other := breakpointTestSpace(3)
	b.pending = &breakpointWrite{before: 0x90, after: 0xcc}
	if err := e.copyBreakpoints(from, other); !errors.Is(err, target.ErrStale) || len(other.breakpoints) != 0 {
		t.Fatalf("copied unconfirmed bytes: %v, %+v", err, other.breakpoints)
	}
}

func TestBreakpointAbandonPreservesLivePeerOwnership(t *testing.T) {
	space := breakpointTestSpace(1)
	bp := breakpointTestSite(space, 0x1000, 1, false)
	p := &process{space: space}
	owner := &thread{tid: 1, process: p, state: target.StateExited, suspended: bp}
	peer := &thread{tid: 2, process: p, state: target.StateRunning}
	space.stepping = owner
	e := &engine{threads: map[int]*thread{1: owner, 2: peer}}
	if err := e.abandonBreakpointStep(owner); !errors.Is(err, target.ErrRunning) {
		t.Fatalf("running peer allowed cleanup: %v", err)
	}
	if owner.suspended != bp || space.stepping != owner || space.breakpoints[bp.addr] != bp {
		t.Fatal("deferred cleanup lost ownership")
	}
	peer.state = target.StateExited
	if err := e.abandonBreakpointStep(owner); err != nil {
		t.Fatal(err)
	}
	if owner.suspended != nil || space.stepping != nil || len(space.breakpoints) != 0 {
		t.Fatal("dead address space retained breakpoint ownership")
	}
}

func TestBreakpointRestoreRetriesCompletedSites(t *testing.T) {
	path, entry := coreAssembly(t, 64, ".text\n.global _start\n_start:\n nop\n nop\n jmp _start\n")
	s, err := Launch(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	for _, addr := range []target.Address{entry, entry + 1} {
		if err := s.AddBreakpoint(addr); err != nil {
			t.Fatal(err)
		}
	}
	err = command(s, func(e *engine) error {
		if err := e.writeByte(s.pid, entry+1, 0x91); err != nil {
			return err
		}
		if err := e.restoreBreakpoints(); !errors.Is(err, target.ErrStale) {
			return errors.New("restore did not reject changed second site")
		}
		space := e.primary.space
		if len(space.breakpoints) != 2 || space.breakpoints[entry].armed || !space.breakpoints[entry+1].armed {
			return errors.New("partial restore progress was not retained")
		}
		if value, err := e.readByte(s.pid, entry); err != nil || value != 0x90 {
			return errors.New("first site's original byte was not restored")
		}
		if err := e.writeByte(s.pid, entry+1, 0xcc); err != nil {
			return err
		}
		if err := e.restoreBreakpoints(); err != nil {
			return err
		}
		if len(space.breakpoints) != 0 {
			return errors.New("successful retry retained restored sites")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var raw [2]byte
	if n, err := s.ReadMemory(entry, raw[:]); err != nil || n != 2 || raw != [2]byte{0x90, 0x90} {
		t.Fatalf("restored bytes=%x count=%d error=%v", raw, n, err)
	}
}

func TestBreakpointRewindRetryKeepsExactPCProvenance(t *testing.T) {
	path, entry := coreAssembly(t, 64, ".text\n.global _start\n_start:\n nop\n jmp _start\n")
	for _, test := range []struct {
		name   string
		offset target.Address
		writes uint64
		want   error
	}{
		{"write-not-applied", 1, 1, nil},
		{"write-applied", 0, 0, nil},
		{"unknown-pc", 2, 0, target.ErrStale},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, err := Launch(path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := s.Close(); err != nil {
					t.Error(err)
				}
			})
			if err := s.AddBreakpoint(entry); err != nil {
				t.Fatal(err)
			}
			stop, err := s.Continue(target.Signal{})
			if err != nil || stop.Reason != target.StopBreakpoint || stop.RawPC == nil || *stop.RawPC != entry+1 {
				t.Fatalf("breakpoint stop=%+v error=%v", stop, err)
			}
			err = command(s, func(e *engine) error {
				current := e.threads[s.pid]
				hit := current.hit
				if hit == nil {
					return errors.New("missing breakpoint hit")
				}
				if err := e.writePC(current.tid, entry+test.offset); err != nil {
					return err
				}
				hit.rewinding = true
				before := current.registerRevision
				err := e.removeBreakpoint(hit.bp)
				if !errors.Is(err, test.want) {
					return errors.New("retry did not enforce the pending PC write endpoints")
				}
				if current.registerRevision != before+test.writes {
					return errors.New("retry rewrote an already confirmed PC")
				}
				if test.want != nil && (current.hit != hit || !hit.rewinding || !hit.bp.armed) {
					return errors.New("rejected retry lost its journal or physical breakpoint")
				}
				if test.want == nil && (current.hit != nil || len(current.process.space.breakpoints) != 0) {
					return errors.New("completed retry retained breakpoint state")
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if *stop.RawPC != entry+1 {
				t.Fatal("PC rollback changed the original raw stop snapshot")
			}
		})
	}
}
