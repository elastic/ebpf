// SPDX-License-Identifier: Elastic-2.0

/*
 * Copyright 2022 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under
 * one or more contributor license agreements. Licensed under the Elastic
 * License 2.0; you may not use this file except in compliance with the Elastic
 * License 2.0.
 */

package testrunner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// This is a JSON type printed by the test binaries (not by EventsTrace), it's
// used all over the place, so define it here to save space
type TestPidInfo struct {
	Tid          int64  `json:"tid"`
	Tgid         int64  `json:"tgid"`
	Ppid         int64  `json:"ppid"`
	Pgid         int64  `json:"pgid"`
	Sid          int64  `json:"sid"`
	CapPermitted uint64 `json:"cap_permitted,string"`
	CapEffective uint64 `json:"cap_effective,string"`
}

// Definitions of types printed by EventsTrace for conversion from JSON
type InitMsg struct {
	InitSuccess bool `json:"probes_initialized"`
	Features    struct {
		BpfTramp bool `json:"bpf_tramp"`
	} `json:"features"`
}

type PidInfo struct {
	Tid         int64 `json:"tid"`
	Tgid        int64 `json:"tgid"`
	Ppid        int64 `json:"ppid"`
	Pgid        int64 `json:"pgid"`
	Sid         int64 `json:"sid"`
	StartTimeNs int64 `json:"start_time_ns"`
}

type CredInfo struct {
	Ruid         int64  `json:"ruid"`
	Rgid         int64  `json:"rgid"`
	Euid         int64  `json:"euid"`
	Egid         int64  `json:"egid"`
	Suid         int64  `json:"suid"`
	Sgid         int64  `json:"sgid"`
	CapPermitted uint64 `json:"cap_permitted,string"`
	CapEffective uint64 `json:"cap_effective,string"`
}

type TtyInfo struct {
	Major int64 `json:"major"`
	Minor int64 `json:"minor"`
}

type NetInfo struct {
	Transport  string `json:"transport"`
	Family     string `json:"family"`
	SourceAddr string `json:"source_address"`
	SourcePort int64  `json:"source_port"`
	DestAddr   string `json:"destination_address"`
	DestPort   int64  `json:"destination_port"`
	NetNs      int64  `json:"network_namespace"`
}

type FileInfo struct {
	Type  string `json:"type"`
	Inode uint64 `json:"inode"`
	Mode  uint64 `json:"mode"`
	Size  uint64 `json:"size"`
	Uid   uint64 `json:"uid"`
	Gid   uint64 `json:"gid"`
	Mtime uint64 `json:"mtime"`
	Ctime uint64 `json:"ctime"`
}

type NsInfo struct {
	Uts    uint32 `json:"uts"`
	Ipc    uint32 `json:"ipc"`
	Mnt    uint32 `json:"mnt"`
	Net    uint32 `json:"net"`
	Cgroup uint32 `json:"cgroup"`
	Time   uint32 `json:"time"`
	Pid    uint32 `json:"pid"`
}

type ProcessForkEvent struct {
	ParentPids PidInfo  `json:"parent_pids"`
	ChildPids  PidInfo  `json:"child_pids"`
	Creds      CredInfo `json:"creds"`
	Ctty       TtyInfo  `json:"ctty"`
	Ns         NsInfo   `json:"ns"`
}

type ProcessExecEvent struct {
	Pids        PidInfo  `json:"pids"`
	Creds       CredInfo `json:"creds"`
	Ctty        TtyInfo  `json:"ctty"`
	IsSetUid    bool     `json:"is_setuid"`
	IsSetGid    bool     `json:"is_setgid"`
	IsMemfd     bool     `json:"is_memfd"`
	InodeNlink  uint64   `json:"inode_nlink"`
	FileName    string   `json:"filename"`
	Cwd         string   `json:"cwd"`
	Argv        []string `json:"argv"`
	Env         []string `json:"env"`
}

type ProcessKernelLoadModuleEvent struct {
	Pids          PidInfo `json:"pids"`
	FileName      string  `json:"filename"`
	ModVersion    string  `json:"mod_version"`
	ModSrcVersion string  `json:"mod_srcversion"`
}

type ProcessShmgetEvent struct {
	Pids          PidInfo `json:"pids"`
	Key           uint32  `json:"key"`
	Size          uint32  `json:"size"`
	ShmFlg        int64   `json:"shmflg"`
}

type MemfdCreateEvent struct {
	Pids           PidInfo `json:"pids"`
	Flags          uint32  `json:"flags"`
	FlagCloexec    bool    `json:"flag_cloexec"`
	FlagAllowSeal  bool    `json:"flag_allow_seal"`
	FlagHugetlb    bool    `json:"flag_hugetlb"`
	FlagNoexecSeal bool    `json:"flag_noexec_seal"`
	FlagExec       bool    `json:"flag_exec"`
	FileName       string  `json:"filename"`
}

type ProcessPtraceEvent struct {
	Pids           PidInfo `json:"pids"`
	ChildPid       int64   `json:"child_pid"`
	Request        int64   `json:"request"`
}

type FileCreateEvent struct {
	Pids  PidInfo  `json:"pids"`
	Path  string   `json:"path"`
	Finfo FileInfo `json:"file_info"`
}

type FileDeleteEvent struct {
	Pids  PidInfo  `json:"pids"`
	Path  string   `json:"path"`
	Finfo FileInfo `json:"file_info"`
}

type FileModifyEvent struct {
	Pids       PidInfo  `json:"pids"`
	Path       string   `json:"path"`
	ChangeType string   `json:"change_type"`
	Finfo      FileInfo `json:"file_info"`
}

type FileRenameEvent struct {
	Pids    PidInfo  `json:"pids"`
	OldPath string   `json:"old_path"`
	NewPath string   `json:"new_path"`
	Finfo   FileInfo `json:"file_info"`
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

type ttyDevInfo struct {
	Major           int64  `json:"major"`
	Minor           int64  `json:"minor"`
	WinsizeRows     int64  `json:"winsize_rows"`
	WinsizeCols     int64  `json:"winsize_cols"`
	Termios_C_Iflag string `json:"termios_c_iflag"`
	Termios_C_Oflag string `json:"termios_c_oflag"`
	Termios_C_Lflag string `json:"termios_c_lflag"`
	Termios_C_Cflag string `json:"termios_c_cflag"`
}

type TtyWriteEvent struct {
	Pids      PidInfo    `json:"pids"`
	Truncated int64      `json:"tty_out_truncated"`
	Out       string     `json:"tty_out"`
	TtyDev    ttyDevInfo `json:"tty"`
}

type NetConnAttemptEvent struct {
	Pids PidInfo `json:"pids"`
	Net  NetInfo `json:"net"`
	Comm string  `json:"comm"`
}

type NetConnAcceptEvent struct {
	Pids PidInfo `json:"pids"`
	Net  NetInfo `json:"net"`
	Comm string  `json:"comm"`
}

type NetBinOut struct {
	PidInfo    TestPidInfo `json:"pid_info"`
	ClientPort int64       `json:"client_port"`
	ServerPort int64       `json:"server_port"`
	NetNs      int64       `json:"netns"`
}

type NetConnCloseEvent struct {
	Pids PidInfo `json:"pids"`
	Net  NetInfo `json:"net"`
	Comm string  `json:"comm"`
}

// path to the test binaries we use to create events for EventsTrace
var testBinaryPath = "/"

// path to the EventsTrace binary
var eventsTracePath = "/EventsTrace"

// Path to the TC filter test binary and probe. This one is weird and lives outside the rest of the test binaries
var (
	tcTestPath = "/BPFTcFilterTests"
	tcObjPath  = "/TcFilter.bpf.o"
)

// init will run at startup and figure out if we're running in the bluebox test env or not,
// and set paths for the binaries as needed
func init() {
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	gitRootPath, err := cmd.CombinedOutput()
	// if there's an error, assume that we're in the test environment,
	// and we're using the root path
	if err != nil {
		fmt.Printf("using root path '%s' for test binary path\n", testBinaryPath)
		return
	}
	// if we have a root path, create the path to test_bins
	// convert GOARCH values to the gcc tuple values
	var arch string
	switch runtime.GOARCH {
	case "amd64":
		arch = "x86_64"
	case "arm64":
		arch = "aarch64"
	default:
		fmt.Printf("unsupported arch %s, reverting to root path for test binaries\n", runtime.GOARCH)
		return
	}
	rootEbpfPath := strings.TrimSpace(string(gitRootPath))
	testBinaryPath = filepath.Join(rootEbpfPath, "testing/test_bins/bin", arch)
	fmt.Printf("using root path '%s' for binary path\n", testBinaryPath)

	// if running in a non-root path, assume we're not in bluebox, set binary path accordingly

	artifactDir := fmt.Sprintf("artifacts-%s", arch)
	eventsTracePath = filepath.Join(rootEbpfPath, artifactDir, "package/bin/EventsTrace")
	tcTestPath = filepath.Join(rootEbpfPath, artifactDir, "package/bin/BPFTcFilterTests")
	tcObjPath = filepath.Join(rootEbpfPath, artifactDir, "package/probes/TcFilter.bpf.o")

	fmt.Printf("using path '%s' for EventsTrace\n", eventsTracePath)
	fmt.Printf("using path '%s' for BPFTcFilterTests\n", tcTestPath)
}

func getEventType(t *testing.T, jsonLine string) string {
	var jsonUnmarshaled struct {
		EventType string `json:"event_type"`
	}

	err := json.Unmarshal([]byte(jsonLine), &jsonUnmarshaled)
	require.NoError(t, err, "error unmarshaling JSON to fetch event type")

	return jsonUnmarshaled.EventType
}

func runTestBin(t *testing.T, binName string, args ...string) []byte {
	cmd := exec.Command(filepath.Join(testBinaryPath, binName), args...)

	output, err := cmd.CombinedOutput()
	// the "correct" way to do this would be errors.Is(), but it doesn't seem to work reliably for the errors that exec returns
	if err != nil {
		if strings.Contains(err.Error(), "no such file") {
			require.NoError(t, err, "test binary %s not found; try `make testbins` to compile test binaries", binName)
		}
	}

	require.NoError(t, err, "error running command %s\n OUTPUT: \n %s", binName, string(output))
	return output
}

func runTestUnmarshalOutput(t *testing.T, binName string, body any) {
	raw := runTestBin(t, binName)
	err := json.Unmarshal(raw, &body)
	require.NoError(t, err, "error unmarshaling output from %s, got:\n %s", binName, string(raw))
}

func TestPidEqual(t *testing.T, tpi TestPidInfo, pi PidInfo) {
	require.Equal(t, pi.Tid, tpi.Tid)
	require.Equal(t, pi.Tgid, tpi.Tgid)
	require.Equal(t, pi.Ppid, tpi.Ppid)
	require.Equal(t, pi.Pgid, tpi.Pgid)
	require.Equal(t, pi.Sid, tpi.Sid)
}

func IsOverlayFsSupported(t *testing.T) bool {
	file, err := os.Open("/proc/filesystems")
	require.NoError(t, err)
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasSuffix(line, "overlay") {
			return true
		}
	}

	err = scanner.Err()
	require.NoError(t, err)

	return false
}

func AssertUint32Equal(a, b uint32) {
	if a != b {
		TestFail(fmt.Sprintf("Test assertion failed 0x%08x != 0x%08x", a, b))
	}
}

func AssertUint32NotEqual(a, b uint32) {
	if a == b {
		TestFail(fmt.Sprintf("Test assertion failed 0x%08x == 0x%08x", a, b))
	}
}

func PrintBPFDebugOutput() {
	file, err := os.Open("/sys/kernel/debug/tracing/trace")
	if err != nil {
		fmt.Printf("Could not open /sys/kernel/debug/tracing/trace: %s", err)
		return
	}
	defer file.Close()

	b, err := io.ReadAll(file)
	if err != nil {
		fmt.Printf("Could not read /sys/kernel/debug/tracing/trace: %s", err)
		return
	}

	fmt.Print(string(b))
}

func PrintDebugOutputOnFail() {
	fmt.Println("===== CONTENTS OF /sys/kernel/debug/tracing/trace =====")
	PrintBPFDebugOutput()
	fmt.Println("===== END CONTENTS OF /sys/kernel/debug/tracing/trace =====")

	fmt.Print("\n")
	fmt.Println("#######################################################################")
	fmt.Println("# NOTE: /sys/kernel/debug/tracing/trace will only be populated if     #")
	fmt.Println("# -DBPF_ENABLE_PRINTK was set to true in the CMake build.             #")
	fmt.Println("# CI builds do NOT enable -DBPF_ENABLE_PRINTK for performance reasons #")
	fmt.Println("#######################################################################")
	fmt.Print("\n")

	fmt.Println("BPF test failed, see errors and stacktrace above")
}

func FetchNsFromProc() (NsInfo, error) {
	var ns NsInfo

	fetch := func(name string, dst *uint32) error {
		s, err := os.Readlink("/proc/self/ns/" + name)
		if err != nil {
			return err
		}
		start := strings.IndexByte(s, '[')
		if start == -1 {
			return fmt.Errorf("`[` not found for ns %s", name)
		}
		start++
		end := strings.IndexByte(s, ']')
		if end == -1 {
			return fmt.Errorf("`]` not found for ns %s", name)
		}
		v, err := strconv.Atoi(s[start:end])
		if err != nil {
			return err
		}
		*dst = uint32(v)
		return nil
	}

	calls := []struct {
		name string
		dst  *uint32
	}{
		{"uts", &ns.Uts},
		{"ipc", &ns.Ipc},
		{"mnt", &ns.Mnt},
		{"net", &ns.Net},
		{"cgroup", &ns.Cgroup},
		{"time", &ns.Time},
		{"pid", &ns.Pid},
	}
	for _, call := range calls {
		if err := fetch(call.name, call.dst); err != nil {
			return ns, err
		}
	}

	return ns, nil
}
