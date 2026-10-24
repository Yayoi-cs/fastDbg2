package main

import (
	"testing"
)

func TestCLIOptionsQEMUKernel(t *testing.T) {
	for _, args := range [][]string{{"-qemu"}, {"--qemu", "localhost:1234"}, {"--qemu", "unix:/workspace/guest.sock", "--vmlinux", "kernel ELF", "--kernel-slide", "0"}, {"-qemu", "-qemu-host", "::1", "-qemu-port", "2345", "-f", "vmlinux", "--kernel-slide", "0x200000"}} {
		options, err := parseCLIOptions(args)
		if err != nil || !options.qemu || options.qemuAddress == "" {
			t.Fatalf("%v: %+v %v", args, options, err)
		}
	}
	for _, args := range [][]string{{"--qemu"}, {"--qemu", ""}, {"-qemu", "-p", "123"}, {"-qemu", "-f", "vmlinux"}, {"--vmlinux", "file", "--kernel-slide", "0"}, {"-qemu", "--kernel-slide", "0"}, {"-qemu", "-f", "vmlinux", "--kernel-slide", "0", "--", "arg"}, {"-qemu", "-qemu-port", "65536"}, {"-qemu", "-qemu"}, {"-qemu", "--vmlinux", "a", "-f", "b", "--kernel-slide", "0"}} {
		if _, err := parseCLIOptions(args); err == nil {
			t.Fatalf("invalid kernel options accepted: %v", args)
		}
	}
}
