// SPDX-License-Identifier: Elastic-2.0

/*
 * Copyright 2022 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under
 * one or more contributor license agreements. Licensed under the Elastic
 * License 2.0; you may not use this file except in compliance with the Elastic
 * License 2.0.
 */

package testrunner

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
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
		// trampolines (it's super ubiquitous on x86 as far as I can see), so
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

	// test for IPv6 support feature
	if _, err := os.Stat("/proc/sys/net/ipv6"); err == nil {
		require.True(t, et.InitMsg.Features.IPv6)
	} else {
		require.False(t, et.InitMsg.Features.IPv6)
	}
}

func ForkExit(t *testing.T, et *Runner) {
	var binOutput TestPidInfo
	runTestUnmarshalOutput(t, "fork_exit", &binOutput)

	var forkEvent ProcessForkEvent
	for {
		et.UnmarshalNextEvent(&forkEvent, "PROCESS_FORK")

		if forkEvent.ParentPids.Tid == binOutput.Tid {
			break
		}
	}

	// Verify forkEvent.ParentPids against bin output
	TestPidEqual(t, binOutput, forkEvent.ParentPids)

	// We don't have the child pid info but can do some internal validations
	// knowing that the parent did a fork(), thus the child process is in the
	// same process group / session but a different thread group
	require.Equal(t, forkEvent.ChildPids.Ppid, forkEvent.ParentPids.Tgid)
	require.Equal(t, forkEvent.ChildPids.Tid, forkEvent.ChildPids.Tgid)
	require.Equal(t, forkEvent.ChildPids.Sid, forkEvent.ParentPids.Sid)
	require.Equal(t, forkEvent.ChildPids.Pgid, forkEvent.ParentPids.Pgid)
	require.NotEqual(t, forkEvent.ChildPids.Tgid, forkEvent.ParentPids.Tgid)

	// Check if all namespace values match /proc/self/ns/*
	ns, err := FetchNsFromProc()
	require.NoError(t, err)
	require.Equal(t, forkEvent.Ns, ns)
}

func ForkExec(t *testing.T, et *Runner) {
	if testBinaryPath != "/" {
		t.Skipf("Test will not work outside test framework")
	}
	var binOutput struct {
		ParentPidInfo TestPidInfo `json:"parent_info"`
		ChildPid      int64       `json:"child_pid"`
		IsSgid        bool        `json:"is_sgid"`
		IsSetuid      bool        `json:"is_setuid"`
		Ruid          int64       `json:"ruid"`
		Euid          int64       `json:"euid"`
		Suid          int64       `json:"suid"`
		Rgid          int64       `json:"rgid"`
		Egid          int64       `json:"egid"`
		Sgid          int64       `json:"sgid"`
	}
	runTestUnmarshalOutput(t, "fork_exec", &binOutput)

	var forkEvent *ProcessForkEvent
	var execEvent *ProcessExecEvent
	// execEvent currently does not work outside the test environment;
	// the calls to capset() break excevl() depending on the path passed to the call.
	// we may want to rewrite that to use a more "correct" set of capabilities.
	for forkEvent == nil || execEvent == nil {
		line := et.GetNextEventOut("PROCESS_FORK", "PROCESS_EXEC")

		eventType := getEventType(t, line)

		switch eventType {
		case "PROCESS_FORK":
			if forkEvent == nil {
				forkEvent = new(ProcessForkEvent)
				err := json.Unmarshal([]byte(line), &forkEvent)
				require.NoError(t, err, "error unmarshaling forkEvent")

				if forkEvent.ChildPids.Tgid != binOutput.ChildPid {
					forkEvent = nil
				} else {
					t.Logf("got fork event...")
				}
			}
		case "PROCESS_EXEC":
			if execEvent == nil {
				execEvent = new(ProcessExecEvent)
				t.Logf("got exec: %s", line)
				err := json.Unmarshal([]byte(line), &execEvent)
				require.NoError(t, err, "error unmarshaling processExecEvent")
				if execEvent.Pids.Tgid != binOutput.ChildPid {
					execEvent = nil
				} else {
					t.Logf("got exec event...")
				}
			}

		}
	}

	require.Equal(t, forkEvent.Creds.CapPermitted, uint64(0x00000000ffffffff))
	require.Equal(t, forkEvent.Creds.CapEffective, uint64(0x00000000f0f0f0f0))

	require.Equal(t, execEvent.Creds.Ruid, binOutput.Ruid)
	require.Equal(t, execEvent.Creds.Rgid, binOutput.Rgid)
	require.Equal(t, execEvent.Creds.Euid, binOutput.Euid)
	require.Equal(t, execEvent.Creds.Egid, binOutput.Egid)
	require.Equal(t, execEvent.Creds.Suid, binOutput.Suid)
	require.Equal(t, execEvent.Creds.Sgid, binOutput.Sgid)

	require.Equal(t, execEvent.Creds.CapPermitted, uint64(0x000001ffffffffff))
	require.Equal(t, execEvent.Creds.CapEffective, uint64(0x000001ffffffffff))
	require.Equal(t, execEvent.FileName, "./do_nothing")
	require.Equal(t, execEvent.Argv[0], "./do_nothing")
	require.Equal(t, execEvent.Env[0], "TEST_ENV_KEY1=TEST_ENV_VAL1")
	require.Equal(t, execEvent.Env[1], "TEST_ENV_KEY2=TEST_ENV_VAL2")
	require.Equal(t, execEvent.Cwd, "/")
}

func FileCreate(t *testing.T, et *Runner) {
	var binOutput struct {
		PidInfo      TestPidInfo `json:"pid_info"`
		FileNameOrig string      `json:"filename_orig"`
		FileNameNew  string      `json:"filename_new"`
	}
	runTestUnmarshalOutput(t, "create_rename_delete_file", &binOutput)

	var fileCreateEvent FileCreateEvent
	for {
		et.UnmarshalNextEvent(&fileCreateEvent, "FILE_CREATE")
		if fileCreateEvent.Pids.Tid == binOutput.PidInfo.Tid {
			break
		}
	}

	TestPidEqual(t, binOutput.PidInfo, fileCreateEvent.Pids)
	require.Equal(t, fileCreateEvent.Path, binOutput.FileNameOrig)
	// File Info
	require.Equal(t, fileCreateEvent.Finfo.Type, "FILE")
	require.NotEqual(t, fileCreateEvent.Finfo.Inode, uint64(0))
	require.Equal(t, fileCreateEvent.Finfo.Mode, uint64(100644))
	require.Equal(t, fileCreateEvent.Finfo.Size, uint64(0))
	require.Equal(t, fileCreateEvent.Finfo.Uid, uint64(0))
	require.Equal(t, fileCreateEvent.Finfo.Gid, uint64(0))
}

func FileDelete(t *testing.T, et *Runner) {
	var binOutput struct {
		PidInfo      TestPidInfo `json:"pid_info"`
		FileNameOrig string      `json:"filename_orig"`
		FileNameNew  string      `json:"filename_new"`
	}
	runTestUnmarshalOutput(t, "create_rename_delete_file", &binOutput)

	var fileDeleteEvent FileDeleteEvent
	for {
		et.UnmarshalNextEvent(&fileDeleteEvent, "FILE_DELETE")
		if fileDeleteEvent.Pids.Tid == binOutput.PidInfo.Tid {
			break
		}
	}

	TestPidEqual(t, binOutput.PidInfo, fileDeleteEvent.Pids)
	require.Equal(t, fileDeleteEvent.Path, binOutput.FileNameNew)
	// File Info
	require.Equal(t, fileDeleteEvent.Finfo.Type, "FILE")
	require.NotEqual(t, fileDeleteEvent.Finfo.Inode, 0)
	require.Equal(t, fileDeleteEvent.Finfo.Mode, uint64(100777))
	require.Equal(t, fileDeleteEvent.Finfo.Size, uint64(0))
	require.Equal(t, fileDeleteEvent.Finfo.Uid, uint64(0))
	require.Equal(t, fileDeleteEvent.Finfo.Gid, uint64(0))
}

func FileRename(t *testing.T, et *Runner) {
	var binOutput struct {
		PidInfo      TestPidInfo `json:"pid_info"`
		FileNameOrig string      `json:"filename_orig"`
		FileNameNew  string      `json:"filename_new"`
	}
	runTestUnmarshalOutput(t, "create_rename_delete_file", &binOutput)

	var fileRenameEvent FileRenameEvent
	for {
		et.UnmarshalNextEvent(&fileRenameEvent, "FILE_RENAME")
		if fileRenameEvent.Pids.Tid == binOutput.PidInfo.Tid {
			break
		}
	}

	TestPidEqual(t, binOutput.PidInfo, fileRenameEvent.Pids)
	require.Equal(t, fileRenameEvent.OldPath, binOutput.FileNameOrig)
	require.Equal(t, fileRenameEvent.NewPath, binOutput.FileNameNew)
	// File Info
	require.Equal(t, fileRenameEvent.Finfo.Type, "FILE")
	require.NotEqual(t, fileRenameEvent.Finfo.Inode, uint64(0))
	require.Equal(t, fileRenameEvent.Finfo.Mode, uint64(100644))
	require.Equal(t, fileRenameEvent.Finfo.Size, uint64(0))
	require.Equal(t, fileRenameEvent.Finfo.Uid, uint64(0))
	require.Equal(t, fileRenameEvent.Finfo.Gid, uint64(0))
}

func Setuid(t *testing.T, et *Runner) {
	var binOutput struct {
		PidInfo TestPidInfo `json:"pid_info"`
		NewRuid int64       `json:"new_ruid"`
		NewEuid int64       `json:"new_euid"`
	}
	runTestUnmarshalOutput(t, "setreuid", &binOutput)

	var setUidEvent SetUidEvent
	for {
		et.UnmarshalNextEvent(&setUidEvent, "PROCESS_SETUID")
		if setUidEvent.Pids.Tid == binOutput.PidInfo.Tid {
			break
		}
	}

	require.Equal(t, binOutput.NewRuid, setUidEvent.NewRuid)
	require.Equal(t, binOutput.NewEuid, setUidEvent.NewEuid)
	TestPidEqual(t, binOutput.PidInfo, setUidEvent.Pids)
}

func Setgid(t *testing.T, et *Runner) {
	var binOutput struct {
		PidInfo TestPidInfo `json:"pid_info"`
		NewRgid int64       `json:"new_rgid"`
		NewEgid int64       `json:"new_egid"`
	}
	runTestUnmarshalOutput(t, "setregid", &binOutput)

	var setGidEvent SetGidEvent
	for {
		et.UnmarshalNextEvent(&setGidEvent, "PROCESS_SETGID")
		if setGidEvent.Pids.Tid == binOutput.PidInfo.Tid {
			break
		}
	}

	require.Equal(t, binOutput.NewRgid, setGidEvent.NewRgid)
	require.Equal(t, binOutput.NewEgid, setGidEvent.NewEgid)
	TestPidEqual(t, binOutput.PidInfo, setGidEvent.Pids)
}

func FileCreateContainer(t *testing.T, et *Runner) {
	var binOutput struct {
		ChildPid     int64  `json:"child_pid"`
		FileNameOrig string `json:"filename_orig"`
		FileNameNew  string `json:"filename_new"`
	}
	runTestUnmarshalOutput(t, "create_rename_delete_file_container", &binOutput)

	var fileCreateEvent FileCreateEvent
	for {
		et.UnmarshalNextEvent(&fileCreateEvent, "FILE_CREATE")
		if fileCreateEvent.Pids.Tgid == binOutput.ChildPid {
			break
		}
	}
	require.Equal(t, fileCreateEvent.Path, binOutput.FileNameOrig)
}

func FileRenameContainer(t *testing.T, et *Runner) {
	var binOutput struct {
		ChildPid     int64  `json:"child_pid"`
		FileNameOrig string `json:"filename_orig"`
		FileNameNew  string `json:"filename_new"`
	}
	runTestUnmarshalOutput(t, "create_rename_delete_file_container", &binOutput)

	var fileRenameEvent FileRenameEvent
	for {
		et.UnmarshalNextEvent(&fileRenameEvent, "FILE_RENAME")
		if fileRenameEvent.Pids.Tgid == binOutput.ChildPid {
			break
		}
	}

	require.Equal(t, fileRenameEvent.OldPath, binOutput.FileNameOrig)
	require.Equal(t, fileRenameEvent.NewPath, binOutput.FileNameNew)
}

func FileDeleteContainer(t *testing.T, et *Runner) {
	var binOutput struct {
		ChildPid     int64  `json:"child_pid"`
		FileNameOrig string `json:"filename_orig"`
		FileNameNew  string `json:"filename_new"`
	}
	runTestUnmarshalOutput(t, "create_rename_delete_file_container", &binOutput)

	var fileDeleteEvent FileDeleteEvent
	for {
		et.UnmarshalNextEvent(&fileDeleteEvent, "FILE_DELETE")
		if fileDeleteEvent.Pids.Tgid == binOutput.ChildPid {
			break
		}
	}

	require.Equal(t, fileDeleteEvent.Path, binOutput.FileNameNew)
}

func FileModify(t *testing.T, et *Runner) {
	var binOutput struct {
		PidInfo      TestPidInfo `json:"pid_info"`
		FileNameOrig string      `json:"filename_orig"`
		FileNameNew  string      `json:"filename_new"`
	}
	runTestUnmarshalOutput(t, "create_rename_delete_file", &binOutput)

	eventsCount := 4 // chmod, write, writev, truncate
	events := make([]FileModifyEvent, 0, eventsCount)
	for {
		var event FileModifyEvent
		et.UnmarshalNextEvent(&event, "FILE_MODIFY")

		if event.Pids.Tid == binOutput.PidInfo.Tid {
			events = append(events, event)
			eventsCount--
			if eventsCount == 0 {
				break
			}
		}
	}

	// chmod
	require.Equal(t, events[0].Path, binOutput.FileNameNew)
	require.Equal(t, events[0].ChangeType, "PERMISSIONS")
	require.Equal(t, events[0].Finfo.Mode, uint64(100777))

	// write
	require.Equal(t, events[1].Path, binOutput.FileNameNew)
	require.Equal(t, events[1].ChangeType, "CONTENT")
	require.Equal(t, events[1].Finfo.Size, uint64(4))

	// writev
	require.Equal(t, events[2].Path, binOutput.FileNameNew)
	require.Equal(t, events[2].ChangeType, "CONTENT")
	require.Equal(t, events[2].Finfo.Size, uint64(4+5+5))

	// truncate
	require.Equal(t, events[3].Path, binOutput.FileNameNew)
	require.Equal(t, events[3].ChangeType, "CONTENT")
	require.Equal(t, events[3].Finfo.Size, uint64(0))
}

func TtyWrite(t *testing.T, et *Runner) {
	var output struct {
		Pid int64 `json:"pid"`
	}
	runTestUnmarshalOutput(t, "tty_write", &output)

	var ev TtyWriteEvent
	for {
		et.UnmarshalNextEvent(&ev, "PROCESS_TTY_WRITE")
		if ev.Pids.Tgid == output.Pid {
			break
		}
	}

	require.Equal(t, ev.Truncated, int64(0))
	require.Equal(t, ev.Out, "--- OK\n")
	// This is a virtual console, not a pseudo terminal.
	require.Equal(t, ev.TtyDev.Major, int64(4))
	require.Equal(t, ev.TtyDev.WinsizeRows, int64(0))
	require.Equal(t, ev.TtyDev.WinsizeCols, int64(0))
}

func Tcpv4ConnectionAttempt(t *testing.T, et *Runner) {
	binOutput := NetBinOut{}
	runTestUnmarshalOutput(t, "tcpv4_connect", &binOutput)

	var ev NetConnAttemptEvent
	for {
		et.UnmarshalNextEvent(&ev, "NETWORK_CONNECTION_ATTEMPTED")
		if ev.Pids.Tgid == binOutput.PidInfo.Tgid {
			break
		}
	}

	TestPidEqual(t, binOutput.PidInfo, ev.Pids)
	require.Equal(t, ev.Net.Transport, "TCP")
	require.Equal(t, ev.Net.Family, "AF_INET")
	require.Equal(t, ev.Net.SourceAddr, "127.0.0.1")
	require.Equal(t, ev.Net.SourcePort, binOutput.ClientPort)
	require.Equal(t, ev.Net.DestAddr, "127.0.0.1")
	require.Equal(t, ev.Net.DestPort, binOutput.ServerPort)
	require.Equal(t, ev.Net.NetNs, binOutput.NetNs)
	require.Equal(t, ev.Comm, "tcpv4_connect")
}

func MemfdCreate(t *testing.T, et *Runner) {
	binOutput := MemfdBinOut{}
	runTestUnmarshalOutput(t, "poc_memfd_create_exec", &binOutput)

	var memfdCreateEvent *MemfdCreateEvent
	var execEvent *ProcessExecEvent

	type baseEvent struct {
		EventType string `json:"event_type"`
	}

	for memfdCreateEvent == nil || execEvent == nil {
		line := et.GetNextEventOut("PROCESS_MEMFD_CREATE", "PROCESS_EXEC")
		typeField := baseEvent{}
		err := json.Unmarshal([]byte(line), &typeField)
		require.NoError(t, err)

		switch typeField.EventType {
		case "PROCESS_MEMFD_CREATE":
			if memfdCreateEvent != nil {
				continue
			}
			memfdCreateEvent = new(MemfdCreateEvent)
			err := json.Unmarshal([]byte(line), &memfdCreateEvent)
			require.NoError(t, err)
			if memfdCreateEvent.Pids.Tgid != binOutput.PidInfo.Tgid {
				memfdCreateEvent = nil
			}
		case "PROCESS_EXEC":
			if execEvent != nil {
				continue
			}
			execEvent = new(ProcessExecEvent)
			err := json.Unmarshal([]byte(line), &execEvent)
			require.NoError(t, err)
			if execEvent.Pids.Tgid != binOutput.PidInfo.Tgid || !strings.Contains(execEvent.Argv[0], "/proc") {
				execEvent = nil
			}
		}
	}

	TestPidEqual(t, binOutput.PidInfo, memfdCreateEvent.Pids)
	require.Equal(t, binOutput.Flags.Value, memfdCreateEvent.Flags)
	require.Equal(t, binOutput.Flags.MfdCloexec, memfdCreateEvent.FlagCloexec)
	require.Equal(t, binOutput.Flags.MfdAllowSealing, memfdCreateEvent.FlagAllowSeal)
	require.Equal(t, binOutput.Flags.MfdHugetlb, memfdCreateEvent.FlagHugetlb)
	require.Equal(t, binOutput.Flags.MfdNoexecSeal, memfdCreateEvent.FlagNoexecSeal)
	require.Equal(t, binOutput.Flags.MfdExec, memfdCreateEvent.FlagExec)
	require.Equal(t, binOutput.FileName, memfdCreateEvent.FileName)
	require.True(t, execEvent.IsMemfd)
	require.False(t, execEvent.IsSetUid)
	require.False(t, execEvent.IsSetGid)
	require.True(t, execEvent.InodeNlink == 0)
}

func Shmget(t *testing.T, et *Runner) {
	binOutput := ShmgetBinOut{}
	runTestUnmarshalOutput(t, "poc_shmget", &binOutput)

	var ev *ProcessShmgetEvent
	for {
		et.UnmarshalNextEvent(&ev, "PROCESS_SHMGET")
		if ev.Pids.Tgid == binOutput.PidInfo.Tgid {
			break
		}
	}

	require.Equal(t, ev.Key, binOutput.Key)
	require.Equal(t, ev.Size, binOutput.Size)
	require.Equal(t, ev.ShmFlg, binOutput.ShmFlg)
}

func Ptrace(t *testing.T, et *Runner) {
	binOutput := PtraceBinOut{}
	runTestUnmarshalOutput(t, "poc_ptrace", &binOutput)
	var ev ProcessPtraceEvent
	for {
		et.UnmarshalNextEvent(&ev, "PROCESS_PTRACE")
		if ev.Pids.Tgid == binOutput.PtracePid {
			break
		}
	}

	require.Equal(t, ev.Pids.Tgid, binOutput.PtracePid)
	require.Equal(t, ev.Request, binOutput.Request)
	require.Equal(t, ev.ChildPid, binOutput.ChildPid)
}

func Tcpv4ConnectionAccept(t *testing.T, et *Runner) {
	binOutput := NetBinOut{}
	runTestUnmarshalOutput(t, "tcpv4_connect", &binOutput)

	var ev NetConnAcceptEvent
	for {
		et.UnmarshalNextEvent(&ev, "NETWORK_CONNECTION_ACCEPTED")
		if ev.Pids.Tgid == binOutput.PidInfo.Tgid {
			break
		}
	}

	TestPidEqual(t, binOutput.PidInfo, ev.Pids)
	require.Equal(t, ev.Net.Transport, "TCP")
	require.Equal(t, ev.Net.Family, "AF_INET")
	require.Equal(t, ev.Net.SourceAddr, "127.0.0.1")
	require.Equal(t, ev.Net.SourcePort, binOutput.ServerPort)
	require.Equal(t, ev.Net.DestAddr, "127.0.0.1")
	require.Equal(t, ev.Net.DestPort, binOutput.ClientPort)
	require.Equal(t, ev.Net.NetNs, binOutput.NetNs)
	require.Equal(t, ev.Comm, "tcpv4_connect")
}

func Tcpv4ConnectionClose(t *testing.T, et *Runner) {
	binOutput := NetBinOut{}
	runTestUnmarshalOutput(t, "tcpv4_connect", &binOutput)

	var evs []NetConnCloseEvent
	for {
		var ev NetConnCloseEvent
		et.UnmarshalNextEvent(&ev, "NETWORK_CONNECTION_CLOSED")
		if ev.Pids.Tgid != binOutput.PidInfo.Tgid {
			continue
		}
		evs = append(evs, ev)
		if len(evs) == 2 {
			break
		}
	}

	TestPidEqual(t, binOutput.PidInfo, evs[0].Pids)
	require.Equal(t, evs[0].Net.Transport, "TCP")
	require.Equal(t, evs[0].Net.Family, "AF_INET")
	require.Equal(t, evs[0].Net.SourceAddr, "127.0.0.1")
	require.Equal(t, evs[0].Net.SourcePort, binOutput.ClientPort)
	require.Equal(t, evs[0].Net.DestAddr, "127.0.0.1")
	require.Equal(t, evs[0].Net.DestPort, binOutput.ServerPort)
	require.Equal(t, evs[0].Net.NetNs, binOutput.NetNs)
	require.Equal(t, evs[0].Comm, "tcpv4_connect")

	TestPidEqual(t, binOutput.PidInfo, evs[1].Pids)
	require.Equal(t, evs[1].Net.Transport, "TCP")
	require.Equal(t, evs[1].Net.Family, "AF_INET")
	require.Equal(t, evs[1].Net.SourceAddr, "127.0.0.1")
	require.Equal(t, evs[1].Net.SourcePort, binOutput.ServerPort)
	require.Equal(t, evs[1].Net.DestAddr, "127.0.0.1")
	require.Equal(t, evs[1].Net.DestPort, binOutput.ClientPort)
	require.Equal(t, evs[1].Net.NetNs, binOutput.NetNs)
	require.Equal(t, evs[1].Comm, "tcpv4_connect")
}

func Tcpv6ConnectionAttempt(t *testing.T, et *Runner) {
	binOutput := NetBinOut{}
	runTestUnmarshalOutput(t, "tcpv6_connect", &binOutput)

	var ev NetConnAttemptEvent
	for {
		et.UnmarshalNextEvent(&ev, "NETWORK_CONNECTION_ATTEMPTED")
		if ev.Pids.Tgid == binOutput.PidInfo.Tgid {
			break
		}
	}

	TestPidEqual(t, binOutput.PidInfo, ev.Pids)
	require.Equal(t, ev.Net.Transport, "TCP")
	require.Equal(t, ev.Net.Family, "AF_INET6")
	require.Equal(t, ev.Net.SourceAddr, "::1")
	require.Equal(t, ev.Net.SourcePort, binOutput.ClientPort)
	require.Equal(t, ev.Net.DestAddr, "::1")
	require.Equal(t, ev.Net.DestPort, binOutput.ServerPort)
	require.Equal(t, ev.Net.NetNs, binOutput.NetNs)
	require.Equal(t, ev.Comm, "tcpv6_connect")
}

func Tcpv6ConnectionAccept(t *testing.T, et *Runner) {
	binOutput := NetBinOut{}
	runTestUnmarshalOutput(t, "tcpv6_connect", &binOutput)

	var ev NetConnAttemptEvent
	for {
		et.UnmarshalNextEvent(&ev, "NETWORK_CONNECTION_ACCEPTED")
		if ev.Pids.Tgid == binOutput.PidInfo.Tgid {
			break
		}
	}

	TestPidEqual(t, binOutput.PidInfo, ev.Pids)
	require.Equal(t, ev.Net.Transport, "TCP")
	require.Equal(t, ev.Net.Family, "AF_INET6")
	require.Equal(t, ev.Net.SourceAddr, "::1")
	require.Equal(t, ev.Net.SourcePort, binOutput.ServerPort)
	require.Equal(t, ev.Net.DestAddr, "::1")
	require.Equal(t, ev.Net.DestPort, binOutput.ClientPort)
	require.Equal(t, ev.Net.NetNs, binOutput.NetNs)
	require.Equal(t, ev.Comm, "tcpv6_connect")
}

func Tcpv6ConnectionClose(t *testing.T, et *Runner) {
	binOutput := NetBinOut{}
	runTestUnmarshalOutput(t, "tcpv6_connect", &binOutput)

	var evs []NetConnCloseEvent
	for {
		var ev NetConnCloseEvent
		et.UnmarshalNextEvent(&ev, "NETWORK_CONNECTION_CLOSED")
		if ev.Pids.Tgid != binOutput.PidInfo.Tgid {
			continue
		}
		evs = append(evs, ev)
		if len(evs) == 2 {
			break
		}
	}

	TestPidEqual(t, binOutput.PidInfo, evs[0].Pids)
	require.Equal(t, evs[0].Net.Transport, "TCP")
	require.Equal(t, evs[0].Net.Family, "AF_INET6")
	require.Equal(t, evs[0].Net.SourceAddr, "::1")
	require.Equal(t, evs[0].Net.SourcePort, binOutput.ClientPort)
	require.Equal(t, evs[0].Net.DestAddr, "::1")
	require.Equal(t, evs[0].Net.DestPort, binOutput.ServerPort)
	require.Equal(t, evs[0].Net.NetNs, binOutput.NetNs)
	require.Equal(t, evs[0].Comm, "tcpv6_connect")

	TestPidEqual(t, binOutput.PidInfo, evs[1].Pids)
	require.Equal(t, evs[1].Net.Transport, "TCP")
	require.Equal(t, evs[1].Net.Family, "AF_INET6")
	require.Equal(t, evs[1].Net.SourceAddr, "::1")
	require.Equal(t, evs[1].Net.SourcePort, binOutput.ServerPort)
	require.Equal(t, evs[1].Net.DestAddr, "::1")
	require.Equal(t, evs[1].Net.DestPort, binOutput.ClientPort)
	require.Equal(t, evs[1].Net.NetNs, binOutput.NetNs)
	require.Equal(t, evs[1].Comm, "tcpv6_connect")
}

func DNSMonitor(t *testing.T, et *Runner) {
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:53")
	require.NoError(t, err)

	listen, err := net.ListenUDP("udp", addr)
	require.NoError(t, err)
	defer listen.Close()

	conn, err := net.DialUDP("udp", nil, addr)
	require.NoError(t, err)
	defer conn.Close()

	pattern := []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")
	n, err := conn.Write(pattern)
	require.NoError(t, err)
	require.Equal(t, n, len(pattern))

	var buf [256]byte
	n, _, err = listen.ReadFromUDP(buf[:])
	require.NoError(t, err)
	require.Equal(t, n, len(pattern))

	type dnsOutput struct {
		Tgid    int64   `json:"tgid"`
		CapLen  int     `json:"cap_len"`
		OrigLen int     `json:"orig_len"`
		Dir     string  `json:"direction"`
		Data    []uint8 `json:"data"`
	}
	// out
	lineData := dnsOutput{}
	et.UnmarshalNextEvent(&lineData, "DNS_PKT")
	require.Equal(t, int64(os.Getpid()), lineData.Tgid)
	require.Equal(t, 90, lineData.CapLen)
	require.Equal(t, 90, lineData.OrigLen)
	require.Equal(t, "out", lineData.Dir)
	require.Equal(t, pattern, lineData.Data[28:])

	// in
	lineData = dnsOutput{}
	et.UnmarshalNextEvent(&lineData, "DNS_PKT")
	require.Equal(t, int64(os.Getpid()), lineData.Tgid)
	require.Equal(t, 90, lineData.CapLen)
	require.Equal(t, 90, lineData.OrigLen)
	require.Equal(t, "in", lineData.Dir)
	require.Equal(t, pattern, lineData.Data[28:])

}

func TcFilter(t *testing.T, et *Runner) {
	// TC test is weird, and doesn't actually use the
	// return-json-and-check-eventsTrace-output the other tests use
	cmd := exec.Command(tcTestPath)
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, fmt.Sprintf("ELASTIC_EBPF_TC_FILTER_OBJ_PATH=%s", tcObjPath))
	output, err := cmd.Output()
	require.NoError(t, err, "error running Tc filter tests: %s\n", string(output))
}

func TestEbpf(t *testing.T) {
	hasOverlayFS := IsOverlayFsSupported(t)

	// XXX until bluebox does itself
	require.NoError(t, syscall.Mount("", "/sys/fs/cgroup", "cgroup2", 0, ""))

	testCases := []struct {
		name             string
		handle           func(t *testing.T, et *Runner)
		args             []string
		requireOverlayFS bool
	}{
		{"FeaturesCorrect", FeaturesCorrect, []string{}, false},
		{"ForkExit", ForkExit, []string{"--process-fork"}, false},
		{"ForkExec", ForkExec, []string{"--process-fork", "--process-exec"}, false},
		{"FileCreate", FileCreate, []string{"--file-create"}, false},
		{"FileDelete", FileDelete, []string{"--file-delete"}, false},
		{"FileRename", FileRename, []string{"--file-rename"}, false},
		{"Setuid", Setuid, []string{"--process-setuid"}, false},
		{"Setgid", Setgid, []string{"--process-setgid"}, false},
		{"FileModify", FileModify, []string{"--file-modify"}, false},
		{"TtyWrite", TtyWrite, []string{"--process-tty-write"}, false},
		{"Tcpv4ConnectionAttempt", Tcpv4ConnectionAttempt, []string{"--net-conn-attempt"}, false},
		{"Tcpv4ConnectionAccept", Tcpv4ConnectionAccept, []string{"--net-conn-accept"}, false},
		{"Tcpv4ConnectionClose", Tcpv4ConnectionClose, []string{"--net-conn-close"}, false},
		//{"DNSMonitor", DNSMonitor, []string{"--net-conn-dns-pkt"}, false},
		{"Ptrace", Ptrace, []string{"--process-ptrace"}, false},
		{"Shmget", Shmget, []string{"--process-shmget"}, false},
		{"MemfdCreate", MemfdCreate, []string{"--process-memfd-create", "--process-exec"}, false},
		{"TcFilter", TcFilter, []string{}, false},
		{"FileCreateContainer", FileCreateContainer, []string{"--file-create"}, true},
		{"FileRenameContainer", FileRenameContainer, []string{"--file-rename"}, true},
		{"FileDeleteContainer", FileDeleteContainer, []string{"--file-delete"}, true},
	}

	// Conditionally add IPv6 tests if IPv6 is supported
	if _, err := os.Stat("/proc/sys/net/ipv6"); err == nil {
		// Add all IPv6 test cases
		ipv6Tests := []struct {
			name             string
			handle           func(t *testing.T, et *Runner)
			args             []string
			requireOverlayFS bool
		}{
			{"Tcpv6ConnectionAttempt", Tcpv6ConnectionAttempt, []string{"--net-conn-attempt"}, false},
			{"Tcpv6ConnectionAccept", Tcpv6ConnectionAccept, []string{"--net-conn-accept"}, false},
			{"Tcpv6ConnectionClose", Tcpv6ConnectionClose, []string{"--net-conn-close"}, false},
		}

		testCases = append(testCases, ipv6Tests...)
	}

	failed := false

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			if test.requireOverlayFS && !hasOverlayFS {
				t.Skipf("Test requires OverlayFS, not available")
			}
			if failed {
				// small hack to make sure we don't continue to run tests when the first one fails,
				// since a single test failure will dump tons of logs to the console
				// we do this instead of a hard return in order to preserve an exit code
				t.Skip("tests already failed")
			}

			ctx, cancel := context.WithTimeout(context.Background(), time.Minute*5)
			defer cancel()

			run := NewEbpfRunner(ctx, t, test.args...)
			// on return, check for failure. If we've failed, dump stderr and stdout
			defer func() {
				if t.Failed() {
					PrintDebugOutputOnFail()
					run.Dump()
					failed = true
				}
			}()

			run.Start()
			// actually run test
			test.handle(t, run)
			run.Stop()
		})
	}
}
