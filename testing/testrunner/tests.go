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
)

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

		switch getJsonEventType(line) {
		case "PROCESS_FORK":
			forkEvent = new(ProcessForkEvent)
			if err := json.Unmarshal([]byte(line), &forkEvent); err != nil {
				TestFail("failed to unmarshal JSON: ", err)
			}
			if forkEvent.ChildPids.Tgid != binOutput.ChildPid {
				forkEvent = nil
			}
			break
		case "PROCESS_EXEC":
			execEvent = new(ProcessExecEvent)
			if err := json.Unmarshal([]byte(line), &execEvent); err != nil {
				TestFail("failed to unmarshal JSON: ", err)
			}
			if execEvent.Pids.Tgid != binOutput.ChildPid {
				execEvent = nil
			}
			break
		}
	}

	AssertStringsEqual(execEvent.FileName, "./do_nothing")
	AssertStringsEqual(execEvent.Argv, "./do_nothing")
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
