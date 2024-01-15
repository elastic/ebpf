// SPDX-License-Identifier: Elastic-2.0

/*
 * Copyright 2022 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under
 * one or more contributor license agreements. Licensed under the Elastic
 * License 2.0; you may not use this file except in compliance with the Elastic
 * License 2.0.
 */

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

func TestFeaturesCorrect(et *EventsTraceInstance) {
	var utsname syscall.Utsname
	if err := syscall.Uname(&utsname); err != nil {
		TestFail(fmt.Sprintf("Failed to run uname: %s", err))
	}

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
		AssertTrue(et.InitMsg.Features.BpfTramp)
	case "aarch64":
		hasBpfTramp := []string{"6.4.0", "6.4.16", "6.5.0"}

		if contains(hasBpfTramp, kernelVersion) {
			AssertTrue(et.InitMsg.Features.BpfTramp)
		} else {
			AssertFalse(et.InitMsg.Features.BpfTramp)
		}
	default:
		TestFail(fmt.Sprintf("unknown arch %s, please add to the TestFeaturesCorrect test", arch))
	}
}

func TestForkExit(et *EventsTraceInstance) {
	outputStr := runTestBin("fork_exit")
	var binOutput TestPidInfo
	if err := json.Unmarshal(outputStr, &binOutput); err != nil {
		TestFail("failed to unmarshal json: ", err)
	}

	var forkEvent ProcessForkEvent
	for {
		line := et.GetNextEventJson("PROCESS_FORK")

		if err := json.Unmarshal([]byte(line), &forkEvent); err != nil {
			TestFail("failed to unmarshal JSON: ", err)
		}

		if forkEvent.ParentPids.Tid == binOutput.Tid {
			break
		}
	}

	// Verify forkEvent.ParentPids against bin output
	AssertPidInfoEqual(binOutput, forkEvent.ParentPids)

	// We don't have the child pid info but can do some internal validations
	// knowing that the parent did a fork(), thus the child process is in the
	// same process group / session but a different thread group
	AssertInt64Equal(forkEvent.ChildPids.Ppid, forkEvent.ParentPids.Tgid)
	AssertInt64Equal(forkEvent.ChildPids.Tid, forkEvent.ChildPids.Tgid)
	AssertInt64Equal(forkEvent.ChildPids.Sid, forkEvent.ParentPids.Sid)
	AssertInt64Equal(forkEvent.ChildPids.Pgid, forkEvent.ParentPids.Pgid)
	AssertInt64NotEqual(forkEvent.ChildPids.Tgid, forkEvent.ParentPids.Tgid)
}

func TestForkExec(et *EventsTraceInstance) {
	outputStr := runTestBin("fork_exec")
	var binOutput struct {
		ParentPidInfo TestPidInfo `json:"parent_info"`
		ChildPid      int64       `json:"child_pid"`
	}

	if err := json.Unmarshal(outputStr, &binOutput); err != nil {
		TestFail("failed to unmarshal json", err)
	}

	var forkEvent *ProcessForkEvent
	var execEvent *ProcessExecEvent
	for forkEvent == nil || execEvent == nil {
		line := et.GetNextEventJson("PROCESS_FORK", "PROCESS_EXEC")

		eventType, err := getJsonEventType(line)
		if err != nil {
			et.DumpStderr()
			TestFail(fmt.Sprintf("Failed to unmarshal the following JSON: \"%s\": %s", line, err))
		}

		switch eventType {
		case "PROCESS_FORK":
			forkEvent = new(ProcessForkEvent)
			if err := json.Unmarshal([]byte(line), &forkEvent); err != nil {
				TestFail("failed to unmarshal JSON: ", err)
			}
			if forkEvent.ChildPids.Tgid != binOutput.ChildPid {
				forkEvent = nil
			}
		case "PROCESS_EXEC":
			execEvent = new(ProcessExecEvent)
			if err := json.Unmarshal([]byte(line), &execEvent); err != nil {
				TestFail("failed to unmarshal JSON: ", err)
			}
			if execEvent.Pids.Tgid != binOutput.ChildPid {
				execEvent = nil
			}
		}
	}

	AssertUint64Equal(uint64(forkEvent.Creds.CapPermitted), uint64(0x00000000ffffffff))
	AssertUint64Equal(uint64(forkEvent.Creds.CapEffective), uint64(0x00000000f0f0f0f0))
	AssertUint64Equal(uint64(execEvent.Creds.CapPermitted), uint64(0x000001ffffffffff))
	AssertUint64Equal(uint64(execEvent.Creds.CapEffective), uint64(0x000001ffffffffff))
	AssertStringsEqual(execEvent.FileName, "./do_nothing")
	AssertStringsEqual(execEvent.Argv[0], "./do_nothing")
	AssertStringsEqual(execEvent.Env[0], "TEST_ENV_KEY1=TEST_ENV_VAL1")
	AssertStringsEqual(execEvent.Env[1], "TEST_ENV_KEY2=TEST_ENV_VAL2")
	AssertStringsEqual(execEvent.Cwd, "/")
}

func TestFileCreate(et *EventsTraceInstance) {
	outputStr := runTestBin("create_rename_delete_file")
	var binOutput struct {
		PidInfo      TestPidInfo `json:"pid_info"`
		FileNameOrig string      `json:"filename_orig"`
		FileNameNew  string      `json:"filename_new"`
	}
	if err := json.Unmarshal(outputStr, &binOutput); err != nil {
		TestFail("failed to unmarshal json", err)
	}

	var fileCreateEvent FileCreateEvent
	for {
		line := et.GetNextEventJson("FILE_CREATE")
		if err := json.Unmarshal([]byte(line), &fileCreateEvent); err != nil {
			TestFail("failed to unmarshal JSON: ", err)
		}

		if fileCreateEvent.Pids.Tid == binOutput.PidInfo.Tid {
			break
		}
	}

	AssertPidInfoEqual(binOutput.PidInfo, fileCreateEvent.Pids)
	AssertStringsEqual(fileCreateEvent.Path, binOutput.FileNameOrig)
	// File Info
	AssertStringsEqual(fileCreateEvent.Finfo.Type, "FILE")
	AssertUint64NotEqual(fileCreateEvent.Finfo.Inode, 0)
	AssertUint64Equal(fileCreateEvent.Finfo.Mode, 100644)
	AssertUint64Equal(fileCreateEvent.Finfo.Size, 0)
	AssertUint64Equal(fileCreateEvent.Finfo.Uid, 0)
	AssertUint64Equal(fileCreateEvent.Finfo.Gid, 0)
}

func TestFileDelete(et *EventsTraceInstance) {
	outputStr := runTestBin("create_rename_delete_file")
	var binOutput struct {
		PidInfo      TestPidInfo `json:"pid_info"`
		FileNameOrig string      `json:"filename_orig"`
		FileNameNew  string      `json:"filename_new"`
	}
	if err := json.Unmarshal(outputStr, &binOutput); err != nil {
		TestFail("failed to unmarshal json", err)
	}

	var fileDeleteEvent FileDeleteEvent
	for {
		line := et.GetNextEventJson("FILE_DELETE")
		if err := json.Unmarshal([]byte(line), &fileDeleteEvent); err != nil {
			TestFail("failed to unmarshal JSON: ", err)
		}

		if fileDeleteEvent.Pids.Tid == binOutput.PidInfo.Tid {
			break
		}
	}

	AssertPidInfoEqual(binOutput.PidInfo, fileDeleteEvent.Pids)
	AssertStringsEqual(fileDeleteEvent.Path, binOutput.FileNameNew)
	// File Info
	AssertStringsEqual(fileDeleteEvent.Finfo.Type, "FILE")
	AssertUint64NotEqual(fileDeleteEvent.Finfo.Inode, 0)
	AssertUint64Equal(fileDeleteEvent.Finfo.Mode, 100777)
	AssertUint64Equal(fileDeleteEvent.Finfo.Size, 0)
	AssertUint64Equal(fileDeleteEvent.Finfo.Uid, 0)
	AssertUint64Equal(fileDeleteEvent.Finfo.Gid, 0)
}

func TestFileRename(et *EventsTraceInstance) {
	outputStr := runTestBin("create_rename_delete_file")
	var binOutput struct {
		PidInfo      TestPidInfo `json:"pid_info"`
		FileNameOrig string      `json:"filename_orig"`
		FileNameNew  string      `json:"filename_new"`
	}
	if err := json.Unmarshal(outputStr, &binOutput); err != nil {
		TestFail("failed to unmarshal json", err)
	}

	var fileRenameEvent FileRenameEvent
	for {
		line := et.GetNextEventJson("FILE_RENAME")
		if err := json.Unmarshal([]byte(line), &fileRenameEvent); err != nil {
			TestFail("failed to unmarshal JSON: ", err)
		}

		if fileRenameEvent.Pids.Tid == binOutput.PidInfo.Tid {
			break
		}
	}

	AssertPidInfoEqual(binOutput.PidInfo, fileRenameEvent.Pids)
	AssertStringsEqual(fileRenameEvent.OldPath, binOutput.FileNameOrig)
	AssertStringsEqual(fileRenameEvent.NewPath, binOutput.FileNameNew)
	// File Info
	AssertStringsEqual(fileRenameEvent.Finfo.Type, "FILE")
	AssertUint64NotEqual(fileRenameEvent.Finfo.Inode, 0)
	AssertUint64Equal(fileRenameEvent.Finfo.Mode, 100644)
	AssertUint64Equal(fileRenameEvent.Finfo.Size, 0)
	AssertUint64Equal(fileRenameEvent.Finfo.Uid, 0)
	AssertUint64Equal(fileRenameEvent.Finfo.Gid, 0)
}

func TestSetuid(et *EventsTraceInstance) {
	outputStr := runTestBin("setreuid")
	var binOutput struct {
		PidInfo TestPidInfo `json:"pid_info"`
		NewRuid int64       `json:"new_ruid"`
		NewEuid int64       `json:"new_euid"`
	}
	if err := json.Unmarshal(outputStr, &binOutput); err != nil {
		TestFail("failed to unmarshal json", err)
	}

	var setUidEvent SetUidEvent
	for {
		line := et.GetNextEventJson("PROCESS_SETUID")
		if err := json.Unmarshal([]byte(line), &setUidEvent); err != nil {
			TestFail("failed to unmarshal JSON: ", err)
		}

		if setUidEvent.Pids.Tid == binOutput.PidInfo.Tid {
			break
		}
	}

	AssertInt64Equal(binOutput.NewRuid, setUidEvent.NewRuid)
	AssertInt64Equal(binOutput.NewEuid, setUidEvent.NewEuid)
	AssertPidInfoEqual(binOutput.PidInfo, setUidEvent.Pids)
}

func TestSetgid(et *EventsTraceInstance) {
	outputStr := runTestBin("setregid")
	var binOutput struct {
		PidInfo TestPidInfo `json:"pid_info"`
		NewRgid int64       `json:"new_rgid"`
		NewEgid int64       `json:"new_egid"`
	}
	if err := json.Unmarshal(outputStr, &binOutput); err != nil {
		TestFail("failed to unmarshal json", err)
	}

	var setGidEvent SetGidEvent
	for {
		line := et.GetNextEventJson("PROCESS_SETGID")
		if err := json.Unmarshal([]byte(line), &setGidEvent); err != nil {
			TestFail("failed to unmarshal JSON: ", err)
		}

		if setGidEvent.Pids.Tid == binOutput.PidInfo.Tid {
			break
		}
	}

	AssertInt64Equal(binOutput.NewRgid, setGidEvent.NewRgid)
	AssertInt64Equal(binOutput.NewEgid, setGidEvent.NewEgid)
	AssertPidInfoEqual(binOutput.PidInfo, setGidEvent.Pids)
}

func TestFileCreateContainer(et *EventsTraceInstance) {
	outputStr := runTestBin("create_rename_delete_file_container")
	var binOutput struct {
		ChildPid     int64  `json:"child_pid"`
		FileNameOrig string `json:"filename_orig"`
		FileNameNew  string `json:"filename_new"`
	}
	if err := json.Unmarshal(outputStr, &binOutput); err != nil {
		TestFail("failed to unmarshal json", err)
	}

	var fileCreateEvent FileCreateEvent
	for {
		line := et.GetNextEventJson("FILE_CREATE")
		if err := json.Unmarshal([]byte(line), &fileCreateEvent); err != nil {
			TestFail("failed to unmarshal JSON: ", err)
		}

		if fileCreateEvent.Pids.Tgid == binOutput.ChildPid {
			break
		}
	}

	AssertStringsEqual(fileCreateEvent.Path, binOutput.FileNameOrig)
}

func TestFileRenameContainer(et *EventsTraceInstance) {
	outputStr := runTestBin("create_rename_delete_file_container")
	var binOutput struct {
		ChildPid     int64  `json:"child_pid"`
		FileNameOrig string `json:"filename_orig"`
		FileNameNew  string `json:"filename_new"`
	}
	if err := json.Unmarshal(outputStr, &binOutput); err != nil {
		TestFail("failed to unmarshal json", err)
	}

	var fileRenameEvent FileRenameEvent
	for {
		line := et.GetNextEventJson("FILE_RENAME")
		if err := json.Unmarshal([]byte(line), &fileRenameEvent); err != nil {
			TestFail("failed to unmarshal JSON: ", err)
		}

		if fileRenameEvent.Pids.Tgid == binOutput.ChildPid {
			break
		}
	}

	AssertStringsEqual(fileRenameEvent.OldPath, binOutput.FileNameOrig)
	AssertStringsEqual(fileRenameEvent.NewPath, binOutput.FileNameNew)
}

func TestFileDeleteContainer(et *EventsTraceInstance) {
	outputStr := runTestBin("create_rename_delete_file_container")
	var binOutput struct {
		ChildPid     int64  `json:"child_pid"`
		FileNameOrig string `json:"filename_orig"`
		FileNameNew  string `json:"filename_new"`
	}
	if err := json.Unmarshal(outputStr, &binOutput); err != nil {
		TestFail("failed to unmarshal json", err)
	}

	var fileDeleteEvent FileDeleteEvent
	for {
		line := et.GetNextEventJson("FILE_DELETE")
		if err := json.Unmarshal([]byte(line), &fileDeleteEvent); err != nil {
			TestFail("failed to unmarshal JSON: ", err)
		}

		if fileDeleteEvent.Pids.Tgid == binOutput.ChildPid {
			break
		}
	}

	AssertStringsEqual(fileDeleteEvent.Path, binOutput.FileNameNew)
}

func TestFileModify(et *EventsTraceInstance) {
	outputStr := runTestBin("create_rename_delete_file")
	var binOutput struct {
		PidInfo      TestPidInfo `json:"pid_info"`
		FileNameOrig string      `json:"filename_orig"`
		FileNameNew  string      `json:"filename_new"`
	}
	if err := json.Unmarshal(outputStr, &binOutput); err != nil {
		TestFail("failed to unmarshal json", err)
	}

	eventsCount := 4 // chmod, write, writev, truncate
	events := make([]FileModifyEvent, 0, eventsCount)
	for {
		var event FileModifyEvent
		line := et.GetNextEventJson("FILE_MODIFY")
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			TestFail("failed to unmarshal JSON: ", err)
		}

		if event.Pids.Tid == binOutput.PidInfo.Tid {
			events = append(events, event)
			eventsCount--
			if eventsCount == 0 {
				break
			}
		}
	}

	// chmod
	AssertStringsEqual(events[0].Path, binOutput.FileNameNew)
	AssertStringsEqual(events[0].ChangeType, "PERMISSIONS")
	AssertUint64Equal(events[0].Finfo.Mode, 100777)

	// write
	AssertStringsEqual(events[1].Path, binOutput.FileNameNew)
	AssertStringsEqual(events[1].ChangeType, "CONTENT")
	AssertUint64Equal(events[1].Finfo.Size, 4)

	// writev
	AssertStringsEqual(events[2].Path, binOutput.FileNameNew)
	AssertStringsEqual(events[2].ChangeType, "CONTENT")
	AssertUint64Equal(events[2].Finfo.Size, 4+5+5)

	// truncate
	AssertStringsEqual(events[3].Path, binOutput.FileNameNew)
	AssertStringsEqual(events[3].ChangeType, "CONTENT")
	AssertUint64Equal(events[3].Finfo.Size, 0)
}

func TestTtyWrite(et *EventsTraceInstance) {
	out := runTestBin("tty_write")
	var output struct {
		Pid int64 `json:"pid"`
	}
	if err := json.Unmarshal(out, &output); err != nil {
		TestFail("failed to unmarshal json", err)
	}

	var ev TtyWriteEvent
	for {
		line := et.GetNextEventJson("PROCESS_TTY_WRITE")
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			TestFail("failed to unmarshal JSON: ", err)
		}
		if ev.Pids.Tgid == output.Pid {
			break
		}
	}

	AssertInt64Equal(ev.Truncated, 0)
	AssertStringsEqual(ev.Out, "--- OK\n")
	// This is a virtual console, not a pseudo terminal.
	AssertInt64Equal(ev.TtyDev.Major, 4)
	AssertInt64Equal(ev.TtyDev.WinsizeRows, 0)
	AssertInt64Equal(ev.TtyDev.WinsizeCols, 0)
}

func TestTcpv4ConnectionAttempt(et *EventsTraceInstance) {
	outputStr := runTestBin("tcpv4_connect")
	var binOutput struct {
		PidInfo    TestPidInfo `json:"pid_info"`
		ClientPort int64       `json:"client_port"`
		ServerPort int64       `json:"server_port"`
		NetNs      int64       `json:"netns"`
	}

	if err := json.Unmarshal(outputStr, &binOutput); err != nil {
		TestFail("failed to unmarshal json", err)
	}

	var ev NetConnAttemptEvent
	for {
		line := et.GetNextEventJson("NETWORK_CONNECTION_ATTEMPTED")
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			TestFail("failed to unmarshal JSON: ", err)
		}

		if ev.Pids.Tgid == binOutput.PidInfo.Tgid {
			break
		}
	}

	AssertPidInfoEqual(binOutput.PidInfo, ev.Pids)
	AssertStringsEqual(ev.Net.Transport, "TCP")
	AssertStringsEqual(ev.Net.Family, "AF_INET")
	AssertStringsEqual(ev.Net.SourceAddr, "127.0.0.1")
	AssertInt64Equal(ev.Net.SourcePort, binOutput.ClientPort)
	AssertStringsEqual(ev.Net.DestAddr, "127.0.0.1")
	AssertInt64Equal(ev.Net.DestPort, binOutput.ServerPort)
	AssertInt64Equal(ev.Net.NetNs, binOutput.NetNs)
	AssertStringsEqual(ev.Comm, "tcpv4_connect")
}

func TestTcpv4ConnectionAccept(et *EventsTraceInstance) {
	outputStr := runTestBin("tcpv4_connect")
	var binOutput struct {
		PidInfo    TestPidInfo `json:"pid_info"`
		ClientPort int64       `json:"client_port"`
		ServerPort int64       `json:"server_port"`
		NetNs      int64       `json:"netns"`
	}

	if err := json.Unmarshal(outputStr, &binOutput); err != nil {
		TestFail("failed to unmarshal json", err)
	}

	var ev NetConnAcceptEvent
	for {
		line := et.GetNextEventJson("NETWORK_CONNECTION_ACCEPTED")
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			TestFail("failed to unmarshal JSON: ", err)
		}

		if ev.Pids.Tgid == binOutput.PidInfo.Tgid {
			break
		}
	}

	AssertPidInfoEqual(binOutput.PidInfo, ev.Pids)
	AssertStringsEqual(ev.Net.Transport, "TCP")
	AssertStringsEqual(ev.Net.Family, "AF_INET")
	AssertStringsEqual(ev.Net.SourceAddr, "127.0.0.1")
	AssertInt64Equal(ev.Net.SourcePort, binOutput.ServerPort)
	AssertStringsEqual(ev.Net.DestAddr, "127.0.0.1")
	AssertInt64Equal(ev.Net.DestPort, binOutput.ClientPort)
	AssertInt64Equal(ev.Net.NetNs, binOutput.NetNs)
	AssertStringsEqual(ev.Comm, "tcpv4_connect")
}

func TestTcpv4ConnectionClose(et *EventsTraceInstance) {
	outputStr := runTestBin("tcpv4_connect")
	var binOutput struct {
		PidInfo    TestPidInfo `json:"pid_info"`
		ClientPort int64       `json:"client_port"`
		ServerPort int64       `json:"server_port"`
		NetNs      int64       `json:"netns"`
	}

	if err := json.Unmarshal(outputStr, &binOutput); err != nil {
		TestFail("failed to unmarshal json", err)
	}

	var ev NetConnCloseEvent
	for {
		line := et.GetNextEventJson("NETWORK_CONNECTION_CLOSED")
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			TestFail("failed to unmarshal JSON: ", err)
		}

		if ev.Pids.Tgid == binOutput.PidInfo.Tgid {
			break
		}
	}

	// NETWORK_CONNECTION_CLOSED is an interesting case.
	//
	// While NETWORK_CONNECTION_ATTEMPTED is generated exclusively on the
	// client-side via a connect(...) and NETWORK_CONNECTION_ACCEPTED is
	// generated exclusively on the server side via an accept(...)
	// NETWORK_CONNECTION_CLOSED may be generated on either side upon a
	// close(...) of a socket fd. This means that the source and desination
	// ports might be "flipped" depending on what side the connection is on
	// (server/client) for a close event.
	//
	// Our tcpv4_connect binary creates a server and client socket on the same
	// machine, so what port is reported as the source and destination port
	// will vary depending on which socket is closed first (client / server).
	//
	// The test binary closes the server socket first, which counterintuitively
	// results in the _client_ socket being torn down first in the kernel.
	// Thus, our BPF probes report the source/dest ports from the client
	// socket's point of view for the close event. The SourcePort and DestPort
	// assertions below verify this is correct.

	AssertPidInfoEqual(binOutput.PidInfo, ev.Pids)
	AssertStringsEqual(ev.Net.Transport, "TCP")
	AssertStringsEqual(ev.Net.Family, "AF_INET")
	AssertStringsEqual(ev.Net.SourceAddr, "127.0.0.1")
	AssertInt64Equal(ev.Net.SourcePort, binOutput.ClientPort)
	AssertStringsEqual(ev.Net.DestAddr, "127.0.0.1")
	AssertInt64Equal(ev.Net.DestPort, binOutput.ServerPort)
	AssertInt64Equal(ev.Net.NetNs, binOutput.NetNs)
	AssertStringsEqual(ev.Comm, "tcpv4_connect")
}

func TestTcpv6ConnectionAttempt(et *EventsTraceInstance) {
	outputStr := runTestBin("tcpv6_connect")
	var binOutput struct {
		PidInfo    TestPidInfo `json:"pid_info"`
		ClientPort int64       `json:"client_port"`
		ServerPort int64       `json:"server_port"`
		NetNs      int64       `json:"netns"`
	}

	if err := json.Unmarshal(outputStr, &binOutput); err != nil {
		TestFail("failed to unmarshal json", err)
	}

	var ev NetConnAttemptEvent
	for {
		line := et.GetNextEventJson("NETWORK_CONNECTION_ATTEMPTED")
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			TestFail("failed to unmarshal JSON: ", err)
		}

		if ev.Pids.Tgid == binOutput.PidInfo.Tgid {
			break
		}
	}

	AssertPidInfoEqual(binOutput.PidInfo, ev.Pids)
	AssertStringsEqual(ev.Net.Transport, "TCP")
	AssertStringsEqual(ev.Net.Family, "AF_INET6")
	AssertStringsEqual(ev.Net.SourceAddr, "::1")
	AssertInt64Equal(ev.Net.SourcePort, binOutput.ClientPort)
	AssertStringsEqual(ev.Net.DestAddr, "::1")
	AssertInt64Equal(ev.Net.DestPort, binOutput.ServerPort)
	AssertInt64Equal(ev.Net.NetNs, binOutput.NetNs)
	AssertStringsEqual(ev.Comm, "tcpv6_connect")
}

func TestTcpv6ConnectionAccept(et *EventsTraceInstance) {
	outputStr := runTestBin("tcpv6_connect")
	var binOutput struct {
		PidInfo    TestPidInfo `json:"pid_info"`
		ClientPort int64       `json:"client_port"`
		ServerPort int64       `json:"server_port"`
		NetNs      int64       `json:"netns"`
	}

	if err := json.Unmarshal(outputStr, &binOutput); err != nil {
		TestFail("failed to unmarshal json", err)
	}

	var ev NetConnAttemptEvent
	for {
		line := et.GetNextEventJson("NETWORK_CONNECTION_ACCEPTED")
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			TestFail("failed to unmarshal JSON: ", err)
		}

		if ev.Pids.Tgid == binOutput.PidInfo.Tgid {
			break
		}
	}

	AssertPidInfoEqual(binOutput.PidInfo, ev.Pids)
	AssertStringsEqual(ev.Net.Transport, "TCP")
	AssertStringsEqual(ev.Net.Family, "AF_INET6")
	AssertStringsEqual(ev.Net.SourceAddr, "::1")
	AssertInt64Equal(ev.Net.SourcePort, binOutput.ServerPort)
	AssertStringsEqual(ev.Net.DestAddr, "::1")
	AssertInt64Equal(ev.Net.DestPort, binOutput.ClientPort)
	AssertInt64Equal(ev.Net.NetNs, binOutput.NetNs)
	AssertStringsEqual(ev.Comm, "tcpv6_connect")
}

func TestTcpv6ConnectionClose(et *EventsTraceInstance) {
	outputStr := runTestBin("tcpv6_connect")
	var binOutput struct {
		PidInfo    TestPidInfo `json:"pid_info"`
		ClientPort int64       `json:"client_port"`
		ServerPort int64       `json:"server_port"`
		NetNs      int64       `json:"netns"`
	}

	if err := json.Unmarshal(outputStr, &binOutput); err != nil {
		TestFail("failed to unmarshal json", err)
	}

	var ev NetConnCloseEvent
	for {
		line := et.GetNextEventJson("NETWORK_CONNECTION_CLOSED")
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			TestFail("failed to unmarshal JSON: ", err)
		}

		if ev.Pids.Tgid == binOutput.PidInfo.Tgid {
			break
		}
	}

	AssertPidInfoEqual(binOutput.PidInfo, ev.Pids)
	AssertStringsEqual(ev.Net.Transport, "TCP")
	AssertStringsEqual(ev.Net.Family, "AF_INET6")
	AssertStringsEqual(ev.Net.SourceAddr, "::1")
	AssertInt64Equal(ev.Net.SourcePort, binOutput.ClientPort)
	AssertStringsEqual(ev.Net.DestAddr, "::1")
	AssertInt64Equal(ev.Net.DestPort, binOutput.ServerPort)
	AssertInt64Equal(ev.Net.NetNs, binOutput.NetNs)
	AssertStringsEqual(ev.Comm, "tcpv6_connect")
}

func TestTcFilter() {
	cmd := exec.Command("/BPFTcFilterTests")
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, "ELASTIC_EBPF_TC_FILTER_OBJ_PATH=/TcFilter.bpf.o")
	output, err := cmd.Output()

	if err != nil {
		fmt.Println(string(output))
		TestFail(fmt.Sprintf("BPFTcFilterTests failed: %s", err))
	}
}
