package main

import (
	"context"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func FeaturesCorrect(t *testing.T, et *Runner) {
	var utsname syscall.Utsname
	err := syscall.Uname(&utsname)
	require.NoError(t, err)

	int8ArrayToString := func(arr [65]int8) string {
		var buf []byte
		for _, el := range arr {
			if el == 0 {
				break
			}
			buf = append(buf, byte(el))
		}
		return string(buf)
	}
	contains := func(s []string, str string) bool {
		for _, el := range s {
			if el == str {
				return true
			}
		}
		return false
	}

	arch := int8ArrayToString(utsname.Machine)
	kernelVersion := int8ArrayToString(utsname.Release)

	switch arch {
	case "x86_64":
		// All x86 kernels in the CI test matrix currently enable bpf
		// trampolines (it's super ubiquitious on x86 as far as I can see), so
		// just assertTrue on BPF tramp support on x86. If a kernel is added
		// that doesn't enable BPF tramps on x86, logic should be added to
		// handle it here.
		require.True(t, et.InitMsg.Features.BpfTramp)
	case "aarch64":
		hasBpfTramp := []string{"6.4.0", "6.4.16", "6.5.0"}

		if contains(hasBpfTramp, kernelVersion) {
			require.True(t, et.InitMsg.Features.BpfTramp)
		} else {
			require.False(t, et.InitMsg.Features.BpfTramp)
		}
	default:
		t.Fatalf("unknown arch %s, please add to the TestFeaturesCorrect test", arch)
	}
}

func TestEbpf(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.TODO(), 90*time.Second)
	defer cancel()

	run := NewEbpfRunner(ctx, t, "--net-conn-dns-pkt")

	run.Start()

	testCases := []struct {
		name   string
		handle func(t *testing.T, et *Runner)
	}{
		{"TestFeaturesCorrect", FeaturesCorrect},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			test.handle(t, run)
		})
	}

}
