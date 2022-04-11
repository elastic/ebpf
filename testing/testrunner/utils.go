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
	"os/exec"
	"reflect"
	"runtime"
	"runtime/debug"
	"syscall"
)

// This is a JSON type printed by the test binaries (not by EventsTrace), it's
// used all over the place, so define it here to save space
type TestPidInfo struct {
	Tid  int64 `json:"tid"`
	Tgid int64 `json:"tgid"`
	Ppid int64 `json:"ppid"`
	Pgid int64 `json:"pgid"`
	Sid  int64 `json:"sid"`
}

// Definitions of types printed by EventsTrace for conversion from JSON
type PidInfo struct {
	Tid         int64 `json:"tid"`
	Tgid        int64 `json:"tgid"`
	Ppid        int64 `json:"ppid"`
	Pgid        int64 `json:"pgid"`
	Sid         int64 `json:"sid"`
	StartTimeNs int64 `json:"start_time_ns"`
}

type CredInfo struct {
	Ruid int64 `json:"ruid"`
	Rgid int64 `json:"rgid"`
	Euid int64 `json:"euid"`
	Egid int64 `json:"egid"`
	Suid int64 `json:"suid"`
	Sgid int64 `json:"sgid"`
}

type TtyInfo struct {
	Major int64 `json:"major"`
	Minor int64 `json:"minor"`
}

type ProcessForkEvent struct {
	ParentPids PidInfo `json:"parent_pids"`
	ChildPids  PidInfo `json:"child_pids"`
}

type ProcessExecEvent struct {
	Pids     PidInfo  `json:"pids"`
	Creds    CredInfo `json:"creds"`
	Ctty     TtyInfo  `json:"creds"`
	FileName string   `json:"filename"`
	Cwd      string   `json:"cwd"`
	Argv     string   `json:"argv"`
}

type FileCreateEvent struct {
	Pids PidInfo `json:"pids"`
	Path string  `json:"path"`
}

type FileDeleteEvent struct {
	Pids PidInfo `json:"pids"`
	Path string  `json:"path"`
}

type FileRenameEvent struct {
	Pids    PidInfo `json:"pids"`
	OldPath string  `json:"old_path"`
	NewPath string  `json:"new_path"`
}

type SetUidEvent struct {
	Pids    PidInfo `json:"pids"`
	NewRuid int64   `json:"new_ruid"`
	NewEuid int64   `json:"new_euid"`
}

type SetGidEvent struct {
	Pids    PidInfo `json:"pids"`
	NewRgid int64   `json:"new_rgid"`
	NewEgid int64   `json:"new_egid"`
}

func getJsonEventType(jsonLine string) string {
	var jsonUnmarshaled struct {
		EventType string `json:"event_type"`
	}

	err := json.Unmarshal([]byte(jsonLine), &jsonUnmarshaled)
	if err != nil {
		TestFail(err)
	}

	return jsonUnmarshaled.EventType
}

func runTestBin(binName string) []byte {
	cmd := exec.Command(fmt.Sprintf("/%s", binName))

	output, err := cmd.Output()
	if err != nil {
		fmt.Println(string(err.(*exec.ExitError).Stderr))
		fmt.Println(string(output))
		TestFail(fmt.Sprintf("Could not run test binary: %s", err))
	}

	return output
}

func AssertPidInfoEqual(tpi TestPidInfo, pi PidInfo) {
	AssertInt64Equal(pi.Tid, tpi.Tid)
	AssertInt64Equal(pi.Tgid, tpi.Tgid)
	AssertInt64Equal(pi.Ppid, tpi.Ppid)
	AssertInt64Equal(pi.Pgid, tpi.Pgid)
	AssertInt64Equal(pi.Sid, tpi.Sid)
}

func AssertStringsEqual(a, b string) {
	if a != b {
		TestFail(fmt.Sprintf("Test assertion failed %s != %s", a, b))
	}
}

func AssertInt64Equal(a, b int64) {
	if a != b {
		TestFail(fmt.Sprintf("Test assertion failed %d != %d", a, b))
	}
}

func AssertInt64NotEqual(a, b int64) {
	if a == b {
		TestFail(fmt.Sprintf("Test assertion failed %d == %d", a, b))
	}
}

func TestFail(v ...interface{}) {
	fmt.Println(v...)

	fmt.Println("===== STACKTRACE FOR FAILED TEST =====")
	debug.PrintStack()
	fmt.Println("===== END STACKTRACE FOR FAILED TEST =====")

	fmt.Println("")
	fmt.Println("####################################################")
	fmt.Println("# BPF test failed, see errors and stacktrace above #")
	fmt.Println("####################################################")
	fmt.Println("")

	PowerOff()
}

func AllTestsPassed() {
	fmt.Println("ALL BPF TESTS PASSED")
}

func PowerOff() {
	fmt.Println("Powering off VM")
	if err := syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF); err != nil {
		panic(fmt.Sprintf("Power off failed: %s", err))
	}
}

func RunTest(f func(*EventsTraceInstance), args ...string) {
	testFuncName := runtime.FuncForPC(reflect.ValueOf(f).Pointer()).Name()

	et := NewEventsTrace(args...)
	et.Start()

	f(et) // Will dump info and shutdown if test fails

	fmt.Println("test passed: ", testFuncName)

	if err := et.Stop(); err != nil {
		TestFail(fmt.Sprintf("Could not stop EventsTrace binary: %s", err))
	}
}
