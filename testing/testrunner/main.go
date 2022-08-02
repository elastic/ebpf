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
	RunTest(TestFeaturesCorrect)
	RunTest(TestForkExit, "--process-fork")
	RunTest(TestForkExec, "--process-fork", "--process-exec")
	RunTest(TestSetuid, "--process-setuid")
	RunTest(TestSetgid, "--process-setgid")
	RunTest(TestFileCreate, "--file-create")
	RunTest(TestFileDelete, "--file-delete")
	RunTest(TestFileRename, "--file-rename")

	// TODO: Re-enable tty_write probe when BTF issues are fixed
	// RunTest(TestTtyWrite, "--process-tty-write")

	// These tests rely on overlayfs support. Distro kernels commonly compile
	// overlayfs as a module, thus it's not available to us in our
	// minimal/bzImage-only approach (attempting to mount an overlay fs will
	// result in ENODEV if the module isn't loaded). The mainline kernel build
	// script ensures overlayfs is compiled into the kernel, so just skip these
	// tests if we're on a distro kernel that we can't use overlayfs on.
	if IsOverlayFsSupported() {
		RunTest(TestFileCreateContainer, "--file-create")
		RunTest(TestFileRenameContainer, "--file-rename")
		RunTest(TestFileDeleteContainer, "--file-delete")
	} else {
		fmt.Println("Overlayfs kernel module not loaded, not running ovl tests")
	}

	AllTestsPassed()
}
