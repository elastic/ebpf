// SPDX-License-Identifier: Elastic-2.0

/*
 * Copyright 2022 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under
 * one or more contributor license agreements. Licensed under the Elastic
 * License 2.0; you may not use this file except in compliance with the Elastic
 * License 2.0.
 */

package main

import (
	"fmt"
)

func main() {
	RunEventsTest(TestFeaturesCorrect)
	RunEventsTest(TestForkExit, "--process-fork")
	RunEventsTest(TestForkExec, "--process-fork", "--process-exec")
	RunEventsTest(TestSetuid, "--process-setuid")
	RunEventsTest(TestSetgid, "--process-setgid")
	RunEventsTest(TestTtyWrite, "--process-tty-write")

	RunEventsTest(TestFileCreate, "--file-create")
	RunEventsTest(TestFileDelete, "--file-delete")
	RunEventsTest(TestFileRename, "--file-rename")
	RunEventsTest(TestFileModify, "--file-modify")

	RunEventsTest(TestTcpv4ConnectionAttempt, "--net-conn-attempt")
	RunEventsTest(TestTcpv4ConnectionAccept, "--net-conn-accept")
	RunEventsTest(TestTcpv4ConnectionClose, "--net-conn-close")
	RunEventsTest(TestTcpv6ConnectionAttempt, "--net-conn-attempt")
	RunEventsTest(TestTcpv6ConnectionAccept, "--net-conn-accept")
	RunEventsTest(TestTcpv6ConnectionClose, "--net-conn-close")

	RunTest(TestTcFilter)

	// These tests rely on overlayfs support. Distro kernels commonly compile
	// overlayfs as a module, thus it's not available to us in our
	// minimal/bzImage-only approach (attempting to mount an overlay fs will
	// result in ENODEV if the module isn't loaded). The mainline kernel build
	// script ensures overlayfs is compiled into the kernel, so just skip these
	// tests if we're on a distro kernel that we can't use overlayfs on.
	if IsOverlayFsSupported() {
		RunEventsTest(TestFileCreateContainer, "--file-create")
		RunEventsTest(TestFileRenameContainer, "--file-rename")
		RunEventsTest(TestFileDeleteContainer, "--file-delete")
	} else {
		fmt.Println("Overlayfs kernel module not loaded, not running ovl tests")
	}

	AllTestsPassed()
}
